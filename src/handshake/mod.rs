use std::io::Error;

use bufstream::BufStream;
use futures::{Poll, Sink, StartSend, Stream};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::Framed;

use codec::Codec;
use message::Frame;

mod client;
mod http;
mod server;

pub use self::client::{Client, connect};
pub use self::server::{Accept, accept};

const WS_GUID: &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A raw websocket stream without protocol handling.
///
/// This will eventually be replaced with `impl Trait` once that is
/// stable.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct WebSocket<T: AsyncRead + AsyncWrite>(Framed<BufStream<T>, Codec>);

impl<T: AsyncRead + AsyncWrite> Sink for WebSocket<T> {
    type SinkItem = Frame;
    type SinkError = Error;

    fn start_send(&mut self, item: Self::SinkItem)
            -> StartSend<Self::SinkItem, Self::SinkError> {
        self.0.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.0.poll_complete()
    }
}

impl<T: AsyncRead + AsyncWrite> Stream for WebSocket<T> {
    type Item = Frame;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.0.poll()
    }
}
