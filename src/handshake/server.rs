use std::ascii::AsciiExt;
use std::io::{Error, ErrorKind};
use std::str;

use base64;
use futures::{Future, Poll};
use sha1;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::Framed;
use tokio_io::io as tk_io;

use codec::Codec;
use transport::Settings;

/// Asynchronously accepts a websocket connection on the given socket.
///
/// Returns a future that, when it resolves, contains a combined `Stream` /
/// `Sink` object representing the websocket. It can then be used in turn to
/// construct a `Transport` that can be bound as server protocol.
pub fn accept<T>(io: T, cfg: &Settings) -> Accept<T>
        where T: 'static + AsyncRead + AsyncWrite {
    assert!(cfg.max_message_size > 0);

    let max_size = cfg.max_message_size;
    let fut = super::ParseRequest::new(io)
        .and_then(|(io, req)| {
            if &req.method != "GET" {
                return Err(Error::new(ErrorKind::InvalidData, "Request method not GET"));
            }

            let has_upgr_h = req.headers.iter()
                .filter(|h| h.0.eq_ignore_ascii_case("Connection"))
                .filter_map(|h| str::from_utf8(&h.1).ok())
                .map(|part| part.trim())
                .any(|part| part.eq_ignore_ascii_case("Upgrade"));
            if !has_upgr_h {
                return Err(Error::new(ErrorKind::InvalidData, "Missing connection upgrade header"));
            }

            let has_ws_upgr_h = req.headers.iter()
                .filter(|h| h.0.eq_ignore_ascii_case("Upgrade"))
                .filter_map(|h| str::from_utf8(&h.1).ok())
                .map(|part| part.trim())
                .any(|part| part.eq_ignore_ascii_case("websocket"));
            if !has_ws_upgr_h {
                return Err(Error::new(ErrorKind::InvalidData, "Missing websocket upgrade header"));
            }

            let has_version_and_valid = req.headers.iter()
                .filter(|h| h.0.eq_ignore_ascii_case("Sec-WebSocket-Version"))
                .filter_map(|h| str::from_utf8(&h.1).ok())
                .map(|part| part.trim())
                .any(|part| part.eq_ignore_ascii_case("13"));
            if !has_version_and_valid {
                return Err(Error::new(ErrorKind::InvalidData, "Missing Sec-WebSocket-Version header or invalid version"));
            }

            let ws_sec_key = req.headers.into_iter()
                .filter(|h| h.0.eq_ignore_ascii_case("Sec-WebSocket-Key"))
                .filter_map(|h| String::from_utf8(h.1).ok())
                .nth(0);
            if let Some(key) = ws_sec_key {
                Ok((io, key))
            } else {
                Err(Error::new(ErrorKind::InvalidData, "Missing Sec-WebSocket-Key header or found invalid UTF-8"))
            }
        })
        .and_then(|(io, key)| {
            let mut resp = super::Response {
                code: 101,
                headers: Vec::new()
            };

            resp.add_header("Connection", "Upgrade".to_owned());
            resp.add_header("Upgrade", "websocket".to_owned());
            resp.add_header("Sec-WebSocket-Accept", format_nonce_resp(&key));

            tk_io::write_all(io, resp.to_string())
        })
        .map(move |(io, _)| io.framed(Codec::new(false, max_size)));

    Accept(Box::new(fut))
}

/// Creates an RFC 6455 compatible response to the websocket nonce.
fn format_nonce_resp(nonce: &str) -> String {
    let bytes = {
        let mut coder = sha1::Sha1::new();
        coder.update(nonce.trim().as_bytes());
        coder.update(super::WS_GUID.as_bytes());

        coder.digest().bytes()
    };

    base64::encode(&bytes)
}

/// A future that represents the build up of a connection.
///
/// This will eventually be replaced with `impl Trait` once that is
/// stable. Then we will also be able to save the allocation that's
/// currently necessary for getting a clean type out of the `accept`
/// function.
#[must_use = "futures do nothing unless polled"]
pub struct Accept<T>(Box<Future<Item = Framed<T, Codec>, Error = Error>>);

impl<T> Future for Accept<T> {
    type Item = Framed<T, Codec>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use futures::{Future, Stream};
    use tokio_core::net::{TcpListener, TcpStream};
    use tokio_core::reactor::Core;
    use url::Url;

    #[test]
    fn nonce() {
        assert_eq!(
            &format_nonce_resp("  ZPAMZNMVsu0Wq50FzBJrgw==  "),
            "0V7cSmibitc/ejxMdYNNsfGPd+0="
        );
    }

    #[test]
    fn smoke() {
        let confirm = Mutex::new(false);
        let mut core = Core::new().expect("failed to start reactor");
        let handle = core.handle();
        let local_ip = "127.0.0.1:12343".parse().unwrap();

        let srv = TcpListener::bind(&local_ip, &handle)
            .expect("failed to bind listener")
            .incoming()
            .take(1)
            .for_each(|(sock, _)| {
                accept(sock, &Default::default())
                    .map(|_| println!("Successfully accepted connection!"))
            })
            .map_err(|e| panic!("Failed to accept: {:?}", e));

        handle.spawn(srv);

        let url: Url = "ws://localhost:12343".parse().unwrap();
        let fut = TcpStream::connect(&local_ip, &handle)
            .and_then(|sock| ::handshake::connect(sock, url, &Default::default()))
            .map(|_| *confirm.lock().unwrap() = true);

        core.run(fut).expect("failed to connect");

        assert!(*confirm.lock().unwrap(), "Connection didn't run.");
    }
}