use std::ascii::AsciiExt;
use std::io::{Error, ErrorKind};
use std::str;

use base64;
use bufstream::BufStream;
use futures::{Future, Poll};
use rand::{self, Rng};
use sha1;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io as tk_io;
use url::Url;

use codec::Codec;
use handshake::http::{ParseResponse, Request};
use transport::Settings;

/// Asynchronously performs the websocket handshake on the given connection.
///
/// Returns a future that, when it resolves, contains a combined `Stream` /
/// `Sink` object representing the websocket. It can then be used in turn to
/// construct a `Transport` that can be bound as client protocol.
pub fn connect<T>(io: T, url: &Url, cfg: &Settings) -> Client<T>
        where T: 'static + AsyncRead + AsyncWrite {
    assert!(cfg.max_message_size > 0);

    let max_size = cfg.max_message_size;
    let nonce: [u8; 16] = rand::thread_rng().gen();
    let req = format_http_request(&url, &nonce);

    let fut = tk_io::write_all(io, req.to_string().into_bytes())
        .and_then(|(io, _)| ParseResponse::new(BufStream::new(io)))
        .and_then(move |(io, res)| {
            if res.code != 101 {
                return Err(Error::new(ErrorKind::InvalidData, "Response status code not 101"));
            }

            let has_upgr_h = res.headers.iter()
                .filter(|h| h.0.eq_ignore_ascii_case("Connection"))
                .filter_map(|h| str::from_utf8(&h.1).ok())
                .map(|part| part.trim())
                .any(|part| part.eq_ignore_ascii_case("Upgrade"));
            if !has_upgr_h {
                return Err(Error::new(ErrorKind::InvalidData, "Missing connection upgrade header"));
            }

            let has_ws_upgr_h = res.headers.iter()
                .filter(|h| h.0.eq_ignore_ascii_case("Upgrade"))
                .filter_map(|h| str::from_utf8(&h.1).ok())
                .map(|part| part.trim())
                .any(|part| part.eq_ignore_ascii_case("websocket"));
            if !has_ws_upgr_h {
                return Err(Error::new(ErrorKind::InvalidData, "Missing websocket upgrade header"));
            }

            let ws_sec_key_valid = res.headers.iter()
                .filter(|h| h.0.eq_ignore_ascii_case("Sec-WebSocket-Accept"))
                .filter_map(|h| str::from_utf8(&h.1).ok())
                .map(|part| part.trim())
                .nth(0)
                .map(|key| validate_nonce(&nonce, key))
                .unwrap_or(false);
            if !ws_sec_key_valid {
                return Err(Error::new(ErrorKind::InvalidData, "Missing Sec-WebSocket-Key header or invalid websocket key"));
            }

            let has_ext = res.headers.iter()
                .filter(|h| h.0.eq_ignore_ascii_case("Sec-WebSocket-Extensions"))
                .next()
                .is_some();
            if has_ext {
                return Err(Error::new(ErrorKind::InvalidData, "Found websocket extensions when no extensions were requested."));
            }

            let has_proto = res.headers.iter()
                .filter(|h| h.0.eq_ignore_ascii_case("Sec-WebSocket-Protocol") && !h.1.is_empty())
                .next()
                .is_some();
            if has_proto {
                return Err(Error::new(ErrorKind::InvalidData, "Found websocket sub protocols when no protocols were requested."));
            }

            Ok(io)
        })
        .map(move |io| io.framed(Codec::new(true, max_size)))
        .map(|framed| super::WebSocket(framed));

    Client(Box::new(fut))
}

/// Creates the HTTP request used to start up a websocket connection.
fn format_http_request(url: &Url, nonce: &[u8]) -> Request {
    assert_eq!(nonce.len(), 16);

    let domain = url.host_str().expect("missing domain");
    let path = url.path();
    let enc_nonce = base64::encode(nonce);

    let host = if let Some(port) = url.port() {
        format!("{}:{}", domain, port)
    } else {
        domain.to_owned()
    };

    let mut req = Request {
        method: "GET".to_owned(),
        headers: Vec::new(),
        path: path.to_owned(),
    };
    req.add_header("Host", host);
    req.add_header("Connection", "upgrade".to_owned());
    req.add_header("Upgrade", "websocket".to_owned());
    req.add_header("Sec-WebSocket-Version", "13".to_owned());
    req.add_header("Sec-WebSocket-Key", enc_nonce);

    req
}

/// Performs the necessary steps to validate that the server has
/// understood the request for a websocket connection.
fn validate_nonce(nonce: &[u8], response: &str) -> bool {
    assert_eq!(nonce.len(), 16);

    let sha1 = {
        let mut coder = sha1::Sha1::new();

        coder.update(base64::encode(nonce).as_bytes());
        coder.update(super::WS_GUID.as_bytes());
        coder.digest().bytes()
    };

    if let Ok(data) = base64::decode(response.trim()) {
        data == &sha1
    } else {
        false
    }
}

/// A future that represents the build up of a connection.
///
/// This will eventually be replaced with `impl Trait` once that is
/// stable. Then we will also be able to save the allocation that's
/// currently necessary for getting a clean type out of the `connect`
/// function.
#[must_use = "futures do nothing unless polled"]
pub struct Client<T: AsyncRead + AsyncWrite>(Box<Future<Item = super::WebSocket<T>, Error = Error>>);

impl<T: AsyncRead + AsyncWrite> Future for Client<T> {
    type Item = super::WebSocket<T>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::TcpStream;
    use std::sync::Mutex;

    use futures::{Sink, Stream};
    use tokio_core::net::TcpStream as TkTcpStream;
    use tokio_core::reactor::Core;

    use message::{Frame, OpCode};

    const TEXT: &'static str = "Hello, World!";

    #[test]
    fn smoke_remote() {
        let confirm = Mutex::new(false);
        let mut core = Core::new().expect("failed to create reactor");

        let stream = TcpStream::connect("echo.websocket.org:80")
            .expect("failed to connect TCP stream");
        let stream = TkTcpStream::from_stream(stream, &core.handle())
            .expect("failed to asyncify stream");
        let url = "ws://echo.websocket.org".parse().expect("failed to parse url");

        let fut = connect(stream, &url, &Default::default())
            .map(|_| ())
            .map_err(|e| println!("Error: {}", e))
            .map(|_| *confirm.lock().unwrap() = true);

        core.run(fut).expect("failed to connect");
        assert!(*confirm.lock().unwrap(), "Connection didn't run.");
    }

    #[test]
    fn smoke_remote_msg() {
        let confirm = Mutex::new(false);
        let mut core = Core::new().expect("failed to create reactor");

        let stream = TcpStream::connect("echo.websocket.org:80")
            .expect("failed to connect TCP stream");
        let stream = TkTcpStream::from_stream(stream, &core.handle())
            .expect("failed to asyncify stream");
        let url = "ws://echo.websocket.org".parse().expect("failed to parse url");

        let fut = connect(stream, &url, &Default::default())
            .and_then(|conn| conn.send(Frame::new_text(TEXT.to_owned())))
            .and_then(|conn| conn.into_future().map_err(|(e, _)| e))
            .map(|(maybe_item, _)| {
                let resp = maybe_item.expect("Missing element!");
                assert_eq!(resp.opcode, OpCode::Text);

                let contents = resp.read_utf8().expect("Failed to parse UTF-8 data!");
                assert_eq!(contents, TEXT);
            })
            .map(|_| ())
            .map_err(|e| println!("Error: {}", e))
            .map(|_| *confirm.lock().unwrap() = true);

        core.run(fut).expect("failed to connect");
        assert!(*confirm.lock().unwrap(), "Connection didn't run.");
    }

    #[test]
    fn nonce() {
        let nonce = [
            0x64, 0xf0, 0x0c, 0x64,
            0xd3, 0x15, 0xb2, 0xed,
            0x16, 0xab, 0x9d, 0x05,
            0xcc, 0x12, 0x6b, 0x83
        ];

        assert!(validate_nonce(&nonce, "0V7cSmibitc/ejxMdYNNsfGPd+0="));
    }
}
