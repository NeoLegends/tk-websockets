use std::collections::VecDeque;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::io::{Error, ErrorKind};
use std::mem;

use bytes::{BufMut, BytesMut};
use futures::{Async, AsyncSink, Poll, Sink, StartSend, Stream};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::codec::{FramedRead, FramedWrite};

use codec::Codec;
use message::{CloseCode, Fragments, Frame, OpCode};

/// The error message when an unfragmented data frame has been received while
/// a fragmented frame is being received.
const DATA_FRAME_DURING_FRAGMENTATION: &'static str = "Received unfragmented binary or data frame while receiving another fragmented frame.";

/// The error message when a fragmented control frame has been received.
const FRAGMENTED_CONTROL_FRAME: &'static str = "Received a fragemented control frame";

/// The error message when the maximum size limit of a  frame as indicated
/// in the settings has been reached.
///
/// The library then fails the websocket connection in order to protect it
/// from being vulnerable to attacks with extremely large messages that should
/// trigger an OOM error.
const MAX_MSG_SIZE_EXCEEDED: &'static str = "Max message size exceeded. Increase the maximum buffer size in the settings or transmit smaller messages";

/// The error message when a send operation is attemped on a closed or closing transport.
const SEND_ON_CLOSED_TP: &'static str = "Send called on closed or closing transport";

/// A small macro just like `try_ready` but to extract the `Some` value
/// of a stream.
macro_rules! try_stream_ready {
    ($val:expr) => ({
        match try_ready!($val) {
            Some(val) => val,
            None => return Ok(Async::Ready(None))
        }
    })
}

/// Settings for building up a `Transport`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    /// The number of fragmented websocket frames a `Transport` can
    /// buffer without reallocating.
    ///
    /// Default: 8
    pub fragments_buf_size: usize,

    /// The maximum size of outgoing frames. Frames larger than this will
    /// be fragmented.
    ///
    /// Default: 32k
    pub fragment_size: usize,

    /// The maximum amount of data a websocket message can take up.
    ///
    /// When this limit is reached the websocket connection will be closed.
    /// The limit applies to all incoming frames, regardless whether they are
    /// fragmented or unfragmented.
    ///
    /// To prevent attacks with an enormous amount of super small frames, this
    /// limit also takes the size of the `Frame` struct itself into account.
    ///
    /// Note: while defragmenting a message, the same amount of memory may be
    /// allocated as temporary buffer. So for each message, you must plan with
    /// double the amount of memory given here as a maximum, if you're tight on
    /// memory.
    ///
    /// Default: 16MB
    pub max_message_size: usize,
}

/// The WebSocket transport implementation.
pub struct Transport<R, W> {
    input: R,
    output: W,
    recv_fragments: Vec<Frame>,
    remaining: Remaining,
    settings: Settings,
    state: State,
}

/// The remaining
#[derive(Clone, Debug)]
struct Remaining {
    buffered: VecDeque<Frame>,
    fragments: Option<Fragments>,
}

/// The inner state of the websocket transport.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum State {
    /// The websocket is in the OPEN state.
    Open,

    /// The websocket is currently closing.
    Closing,

    /// The websocket is closed and no further messages can be sent.
    Closed
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            fragments_buf_size: 8,
            max_message_size: 1024 * 1024 * 16,
            fragment_size: 1024 * 32
        }
    }
}

impl<R, W> Transport<R, W> {
    /// Creates a new `Transport` from the given IO primitives with default settings.
    pub fn new<In, Out>(read: In, write: Out, is_client: bool)
            -> Transport<FramedRead<In, Codec>, FramedWrite<Out, Codec>>
            where In: AsyncRead,
                  Out: AsyncWrite {
        Self::new_with_settings(read, write, is_client, Default::default())
    }

    /// Creates a new `Transport` from the given IO primitives with the given settings.
    pub fn new_with_settings<In, Out>(read: In, write: Out, is_client: bool, settings: Settings)
            -> Transport<FramedRead<In, Codec>, FramedWrite<Out, Codec>>
            where In: AsyncRead,
                  Out: AsyncWrite {
        let codec = Codec::new(is_client, settings.max_message_size);
        let read = FramedRead::new(read, codec);
        let write = FramedWrite::new(write, codec);

        Transport::from_stream_settings(read, write, settings)
    }
}

impl<R, W> Transport<R, W>
    where R: Stream<Item = Frame>,
          W: Sink<SinkItem = Frame> {
    /// Creates a new `Transport` from the given stream and sink.
    ///
    /// This constructor can be used to very naturally compose custom
    /// extension stacks in front of the `Transport`. When creating a
    /// new transport without any extensions, this constructor is simply
    /// passed the `FramedRead` / `FramedWrite`.
    pub fn from_stream(read: R, write: W) -> Self {
        Self::from_stream_settings(read, write, Default::default())
    }

    /// Creates a new `Transport` from the given stream and sink and settings.
    ///
    /// This constructor can be used to very naturally compose custom
    /// extension stacks in front of the `Transport`. When creating a
    /// new transport without any extensions, this constructor is simply
    /// passed the `FramedRead` / `FramedWrite`.
    pub fn from_stream_settings(read: R, write: W, settings: Settings) -> Self {
        let recv_buf = Vec::with_capacity(settings.fragments_buf_size);
        let send_buf = VecDeque::with_capacity(settings.fragments_buf_size);

        Transport {
            input: read,
            output: write,
            recv_fragments: recv_buf,
            remaining: Remaining {
                buffered: send_buf,
                fragments: None
            },
            settings: settings,
            state: State::Open
        }
    }

    /// Closes the WebSocket connection as result of an error.
    fn close(&mut self, code: CloseCode) -> Poll<(), W::SinkError> {
        if self.state != State::Open {
            panic!("Closing multiple times");
        }

        self.state = State::Closing;
        self.send_or_buffer(code.into())
    }

    /// Checks whether the given additional capacity can be allocated and
    /// closes the websocket connection if not.
    fn ensure_capacity(&mut self, additional_size: usize) -> Result<(), Error> {
        let current_buf_size: usize = self.recv_fragments.iter()
            .map(|f| f.payload.len())
            .sum();
        let struct_size = mem::size_of::<Frame>() * (self.recv_fragments.len() + 1);
        let total_size = current_buf_size + additional_size + struct_size;

        if total_size <= self.settings.max_message_size {
            Ok(())
        } else {
            self.close(CloseCode::Size);
            Err(Error::new(ErrorKind::InvalidData, MAX_MSG_SIZE_EXCEEDED))
        }
    }

    /// Attempts to send any remaining buffered fragments.
    fn send_remaining(&mut self) -> Poll<(), W::SinkError> {
        if self.state == State::Closed {
            panic!(SEND_ON_CLOSED_TP);
        }

        // If the fragment send did not succeed, the item is stored in `buffered`.
        while let Some(fgmt) = self.remaining.buffered.pop_front() {
            match self.output.start_send(fgmt) {
                Ok(AsyncSink::Ready) => {},
                Ok(AsyncSink::NotReady(fgmt)) => {
                    self.remaining.buffered.push_front(fgmt);

                    self.output.poll_complete()?;
                    return Ok(Async::NotReady);
                },
                Err(err) => return Err(err)
            }
        }


        // Send remaining fragments, if any.
        if let Some(mut it) = self.remaining.fragments.take() {
            while let Some(fgmt) = it.next() {
                match self.output.start_send(fgmt) {
                    Ok(AsyncSink::Ready) => {},
                    Ok(AsyncSink::NotReady(fgmt)) => {
                        self.remaining.buffered.push_back(fgmt);
                        self.remaining.fragments = Some(it);

                        self.output.poll_complete()?;
                        return Ok(Async::NotReady);
                    },
                    Err(err) => return Err(err)
                }
            }
        }

        self.output.poll_complete()?;
        Ok(Async::Ready(()))
    }

    fn send_or_buffer(&mut self, item: Frame) -> Poll<(), W::SinkError> {
        if self.state == State::Closed {
            panic!(SEND_ON_CLOSED_TP);
        }

        match self.output.start_send(item)? {
            AsyncSink::Ready => self.output.poll_complete(),
            AsyncSink::NotReady(item) => {
                self.remaining.buffered.push_back(item);
                Ok(Async::NotReady)
            }
        }
    }
}

impl<R, W> Sink for Transport<R, W>
    where R: Stream<Item = Frame, Error = Error>,
          W: Sink<SinkItem = Frame, SinkError = Error> {
    type SinkItem = Frame;
    type SinkError = W::SinkError;

    fn start_send(&mut self, item: Self::SinkItem)
            -> StartSend<Self::SinkItem, Self::SinkError> {
        // Ensure we're not sending stuff when the websocket connection
        // is already closed.
        match (self.state, item.opcode) {
            (State::Open, OpCode::Close) => self.state = State::Closing,
            (State::Closing, OpCode::Close) => {},
            (State::Closing, _) |
            (State::Closed, _) => return Err(Error::new(ErrorKind::NotConnected, SEND_ON_CLOSED_TP)),
            _ => {}
        }

        // Always send control frames since they can be interleaved
        // with fragmented messages.
        if item.opcode.is_control() {
            return self.output.start_send(item);
        }

        match self.send_remaining() {
            Ok(Async::Ready(_)) => {},
            Ok(Async::NotReady) => return Ok(AsyncSink::NotReady(item)),
            Err(err) => return Err(err)
        }

        if item.payload().len() > self.settings.fragment_size {
            self.remaining.fragments = Some(item.fragment(self.settings.fragment_size));

            // Return AsyncSink::Ready even if we couldn't send the fragments
            // just yet, because we already consumed the frame.
            match self.send_remaining() {
                Ok(Async::Ready(_)) | Ok(Async::NotReady) => Ok(AsyncSink::Ready),
                Err(err) => Err(err)
            }
        } else {
            self.output.start_send(item)
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.output.poll_complete()
    }
}

impl<R, W> Stream for Transport<R, W>
    where R: Stream<Item = Frame, Error = Error>,
          W: Sink<SinkItem = Frame, SinkError = Error> {
    type Item = Frame;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if self.state == State::Closed {
            return Ok(Async::Ready(None));
        }

        let frame = try_stream_ready!(self.input.poll());

        if !frame.is_finished {
            if frame.opcode.is_control() {
                let _ = self.close(CloseCode::Protocol)?;
                return Err(Error::new(ErrorKind::InvalidData, FRAGMENTED_CONTROL_FRAME));
            }

            self.ensure_capacity(frame.payload.len())?;

            self.recv_fragments.push(frame);
            Ok(Async::NotReady)
        } else if !self.recv_fragments.is_empty() {
            if frame.opcode.is_data() {
                let _ = self.close(CloseCode::Protocol)?;
                return Err(Error::new(ErrorKind::InvalidData, DATA_FRAME_DURING_FRAGMENTATION));
            }

            unimplemented!()
            // let frame_len = frame.payload.len();
            // self.ensure_capacity(frame_len)?;

            // let payload = {
            //     let buf_length = self.recv_fragments.iter()
            //         .fold(frame_len, |len, f| len + f.payload.len());

            //     let mut buf = BytesMut::with_capacity(buf_length);
            //     for buf_frame in self.recv_fragments.iter() {
            //         buf.put(buf_frame.payload);
            //     }
            //     buf.put(frame.payload);

            //     buf
            // };

            // let mut first = self.recv_fragments.drain(..)
            //     .nth(0)
            //     .expect("Missing frame!");
            // first.payload = payload;

            // Ok(Async::Ready(Some(first)))
        } else {
            match frame.opcode {
                OpCode::Close => {
                    match self.state {
                        // The other side wants to close the connection.
                        State::Open => match frame.read_close_code() {
                            Some(cc) => { self.send_or_buffer(cc.into())?; },
                            None => {}
                        },

                        // We're in the process of shutting down the socket and just
                        // received the closing handshake of the other side. The closing
                        // dance is complete and the websocket is shut down.
                        State::Closing => self.state = State::Closed,

                        // Well, we're already closed. Do nothing.
                        State::Closed => {}
                    }

                    Ok(Async::Ready(None))
                },
                OpCode::Ping => {
                    let pong = Frame::new_pong(frame.payload.to_vec());
                    match self.send_or_buffer(pong) {
                        Err(err) => Err(err),
                        _ => Ok(Async::NotReady)
                    }
                },
                _ => Ok(Async::Ready(Some(frame)))
            }
        }
    }
}

impl Remaining {
    pub fn clear(&mut self) {
        self.buffered.clear();
        self.fragments = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::mem;

    use futures::{self, stream};

    struct Null(pub bool);

    impl Sink for Null {
        type SinkItem = Frame;
        type SinkError = Error;

        fn start_send(&mut self, item: Self::SinkItem)
                -> StartSend<Self::SinkItem, Self::SinkError> {
            futures::task::park().unpark();
            Ok(AsyncSink::Ready)
        }

        fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
            Ok(Async::Ready(()))
        }
    }
}