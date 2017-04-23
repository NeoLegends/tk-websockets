use std::collections::VecDeque;
use std::fmt::{self, Debug, Formatter};
use std::io::{Error, ErrorKind};
use std::mem;

use bytes::{BufMut, BytesMut};
use futures::{
    Async, AsyncSink, Poll, StartSend,
    Future, Sink, Stream
};
use tokio_io::AsyncWrite;

use message::{CloseCode, Fragments, Frame, OpCode};

const INITIAL_BUF_CAP: usize = 16;

const CONTINUE_FRAME_SENT: &'static str = "Sending CONTINUE frames directly is not supported. Fragmenting is done transparently in the background, so there is no need to manually send continue frames.";
const MISSING_STATE: &'static str = "Missing transport state. This is a bug. Please contact the authors of tk-websocket.";
const OP_ON_CLOSED_TP: &'static str = "Operation performed on closed or closing transport";

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
    /// The maximum size of outgoing frames. Frames larger than this will
    /// be fragmented.
    ///
    /// Default: 64k
    pub fragment_size: usize,

    /// The maximum amount of data a websocket message can take up.
    ///
    /// When this limit is reached the websocket connection will be closed.
    /// The limit applies to all incoming frames, regardless whether they are
    /// fragmented or unfragmented.
    ///
    /// To prevent attacks with an enormous amount of super small / zero sized
    /// frames, this limit also takes the size of the `Frame` struct itself
    /// into account.
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
pub struct Transport<T> {
    settings: Settings,
    state: Option<State<T>>,
}

/// Fragments waiting to be sent to the other side.
#[derive(Debug)]
struct Remaining {
    buffered: VecDeque<Frame>,
    fragments: Option<Fragments>,
}

/// The inner state of the websocket transport.
enum State<T> {
    /// The websocket is in the OPEN state.
    ///
    /// The tuple layout is to be read as following:
    /// (Reader, Writer, Incoming buffered fragments, Fragments waiting to be sent)
    Open(T, Vec<Frame>, Remaining),

    /// The websocket is currently closing.
    Closing(Box<Future<Item = (), Error = Error>>),

    /// The websocket is closed and no further messages can be sent.
    Closed,
}

trait TransportState<T> {
    fn into_io(&mut self) -> T;

    fn io_mut(&mut self) -> &mut T;

    fn recv_fgmts(&self) -> &[Frame];

    fn recv_fgmts_mut(&mut self) -> &mut Vec<Frame>;

    fn remaining_mut(&mut self) -> &mut Remaining;
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            max_message_size: 1024 * 1024 * 16,
            fragment_size: u16::max_value() as usize
        }
    }
}

impl<T: Debug> Debug for Transport<T> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt.debug_struct("Transport")
            .field("settings", &self.settings)
            .field("state", &self.state)
            .finish()
    }
}

impl<T> Transport<T>
    where T: 'static +
             Stream<Item = Frame, Error = Error> +
             Sink<SinkItem = Frame, SinkError = Error> {
    /// Creates a new `Transport` from the given stream and sink.
    ///
    /// This constructor can be used to very naturally compose custom
    /// extension stacks in front of the `Transport`. When creating a
    /// new transport without any extensions, this constructor is simply
    /// passed the `FramedRead` / `FramedWrite`.
    pub fn new(io: T) -> Self {
        Self::new_with_settings(io, Default::default())
    }

    /// Creates a new `Transport` from the given stream and sink and settings.
    ///
    /// This constructor can be used to very naturally compose custom
    /// extension stacks in front of the `Transport`. When creating a
    /// new transport without any extensions, this constructor is simply
    /// passed the `FramedRead` / `FramedWrite`.
    pub fn new_with_settings(io: T, settings: Settings) -> Self {
        assert!(settings.max_message_size > 0);

        let recv_buf = Vec::with_capacity(INITIAL_BUF_CAP);
        let send_buf = VecDeque::with_capacity(INITIAL_BUF_CAP);
        let remaining = Remaining {
            buffered: send_buf,
            fragments: None
        };

        Transport {
            settings: settings,
            state: Some(State::Open(io, recv_buf, remaining))
        }
    }

    /// Closes the WebSocket connection.
    ///
    /// # Panics
    /// Panics if not called with a close frame.
    fn close<F: Into<Frame>>(&mut self, f: F) {
        self.close_impl(f.into())
    }

    /// Internal implementation of `close` without generics.
    ///
    /// # Panics
    /// Panics if not called with a close frame.
    fn close_impl(&mut self, f: Frame) {
        if f.opcode != OpCode::Close {
            panic!("Close called without close frame.");
        }

        // TODO: Timeout
        let fut = self.state.into_io()
            .send(f)
            .map_err(|e| Error::new(ErrorKind::ConnectionReset, e))
            .and_then(|io| {
                io.filter(|f| f.opcode == OpCode::Close)
                    .into_future()
                    .map_err(|_| Error::new(ErrorKind::ConnectionReset, "Failed to receive close frame."))
            })
            .map(|_| ());

        self.state = Some(State::Closing(Box::new(fut)));
    }

    /// Checks whether the given additional capacity can be allocated and
    /// closes the websocket connection if not.
    fn has_capacity_for(&mut self, additional_size: usize) -> bool {
        let recv_fragments = self.state.recv_fgmts();
        let current_buf_size: usize = recv_fragments.iter()
            .map(|f| f.payload.len())
            .sum();
        let struct_size = mem::size_of::<Frame>() * (recv_fragments.len() + 1);
        let total_size = current_buf_size + additional_size + struct_size;

        total_size <= self.settings.max_message_size
    }

    /// Attempts to send any remaining buffered fragments.
    fn send_remaining(&mut self) -> Poll<(), Error> {
        use self::State::*;

        match *self.state.as_mut().expect(MISSING_STATE) {
            Open(ref mut io, _, ref mut remaining) => {
                // If the fragment send did not succeed, the item is stored in `buffered`.
                while let Some(fgmt) = remaining.buffered.pop_front() {
                    match io.start_send(fgmt) {
                        Ok(AsyncSink::Ready) => {},
                        Ok(AsyncSink::NotReady(fgmt)) => {
                            remaining.buffered.push_front(fgmt);

                            io.poll_complete()?;
                            return Ok(Async::NotReady);
                        },
                        Err(err) => return Err(err)
                    }
                }

                // Send remaining fragments, if any.
                if let Some(mut it) = remaining.fragments.take() {
                    while let Some(fgmt) = it.next() {
                        match io.start_send(fgmt) {
                            Ok(AsyncSink::Ready) => {},
                            Ok(AsyncSink::NotReady(fgmt)) => {
                                remaining.buffered.push_back(fgmt);
                                remaining.fragments = Some(it);

                                io.poll_complete()?;
                                return Ok(Async::NotReady);
                            },
                            Err(err) => return Err(err)
                        }
                    }
                }

                io.poll_complete()
            },
            _ => panic!(OP_ON_CLOSED_TP)
        }
    }

    fn send_or_buffer(&mut self, item: Frame) -> Poll<(), Error> {
        use self::State::*;

        match *self.state.as_mut().expect(MISSING_STATE) {
            Open(ref mut io, _, ref mut remaining) => {
                match io.start_send(item)? {
                    AsyncSink::Ready => io.poll_complete(),
                    AsyncSink::NotReady(item) => {
                        remaining.buffered.push_back(item);
                        Ok(Async::NotReady)
                    }
                }
            },
            _ => panic!(OP_ON_CLOSED_TP)
        }
    }
}

impl<T> Sink for Transport<T>
    where T: 'static +
             Stream<Item = Frame, Error = Error> +
             Sink<SinkItem = Frame, SinkError = Error> {
    type SinkItem = Frame;
    type SinkError = Error;

    fn start_send(&mut self, item: Self::SinkItem)
            -> StartSend<Self::SinkItem, Self::SinkError> {
        use self::State::*;

        match *self.state.as_ref().expect(MISSING_STATE) {
            Closing(_) => return Ok(AsyncSink::NotReady(item)),
            Closed => return Err(Error::new(ErrorKind::NotConnected, OP_ON_CLOSED_TP)),
            _ => {}
        }

        match item.opcode {
            OpCode::Close => {
                self.close(item);
                Ok(AsyncSink::Ready)
            },
            OpCode::Continue => Err(Error::new(ErrorKind::InvalidData, CONTINUE_FRAME_SENT)),
            _ => {
                // Always send control frames since they can be interleaved
                // with fragmented messages.
                if item.opcode.is_control() {
                    return self.state.io_mut().start_send(item);
                }

                match self.send_remaining() {
                    Ok(Async::Ready(_)) => {},
                    Ok(Async::NotReady) => return Ok(AsyncSink::NotReady(item)),
                    Err(err) => return Err(err)
                }

                if item.payload().len() > self.settings.fragment_size {
                    let fgmts = item.fragment(self.settings.fragment_size);
                    self.state.remaining_mut().fragments = Some(fgmts);

                    // Return AsyncSink::Ready even if we couldn't send the fragments
                    // just yet, because we already consumed the frame.
                    match self.send_remaining() {
                        Ok(Async::Ready(_)) | Ok(Async::NotReady) => Ok(AsyncSink::Ready),
                        Err(err) => Err(err)
                    }
                } else {
                    self.state.io_mut().start_send(item)
                }
            }
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        use self::State::*;

        match self.state.take().expect(MISSING_STATE) {
            Open(mut io, recv_fgmts, rem) => {
                let res = io.poll_complete();
                self.state = Some(Open(io, recv_fgmts, rem));
                res
            },
            Closing(mut fut) => match fut.poll() {
                Ok(Async::Ready(_)) => {
                    self.state = Some(Closed);
                    Ok(Async::Ready(()))
                },
                Ok(Async::NotReady) => {
                    self.state = Some(Closing(fut));
                    Ok(Async::NotReady)
                },
                Err(e) => {
                    self.state = Some(Closed);
                    Err(e)
                }
            },
            Closed => Err(Error::new(ErrorKind::NotConnected, OP_ON_CLOSED_TP))
        }
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        use self::State::*;

        match *self.state.as_ref().expect(MISSING_STATE) {
            Open(_, _, _) => self.close(CloseCode::Normal),
            Closed => return Err(Error::new(ErrorKind::NotConnected, OP_ON_CLOSED_TP)),
            _ => {}
        }

        self.poll_complete()
    }
}

impl<T> Stream for Transport<T>
    where T: 'static +
             Stream<Item = Frame, Error = Error> +
             Sink<SinkItem = Frame, SinkError = Error> {
    type Item = Frame;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        use self::State::*;

        let frame = match *self.state.as_mut().expect(MISSING_STATE) {
            Open(ref mut io, _, _) => try_stream_ready!(io.poll()),
            Closing(_) => return Ok(Async::NotReady),
            Closed => return Err(Error::new(ErrorKind::NotConnected, OP_ON_CLOSED_TP))
        };

        if frame.has_rsv() {
            self.close(CloseCode::Protocol);
            return Ok(Async::NotReady);
        } else if !frame.is_finished {
            if frame.opcode.is_control() {
                self.close(CloseCode::Protocol);
                return Ok(Async::NotReady);
            }

            if !self.has_capacity_for(frame.payload.len()) {
                self.close(CloseCode::Size);
                return Ok(Async::NotReady);
            }

            self.state.recv_fgmts_mut().push(frame);
            Ok(Async::NotReady)
        } else if !self.state.recv_fgmts().is_empty() {
            if frame.opcode.is_data() {
                self.close(CloseCode::Protocol);
                return Ok(Async::NotReady);
            }

            let frame_len = frame.payload.len();
            if !self.has_capacity_for(frame_len) {
                self.close(CloseCode::Size);
                return Ok(Async::NotReady);
            }

            let (rsv1, rsv2, rsv3, opcode) = {
                let first = &self.state.recv_fgmts()[0];
                (first.rsv1, first.rsv2, first.rsv3, first.opcode)
            };

            if rsv1 || rsv1 || rsv3 {
                self.close(CloseCode::Extension);
                return Ok(Async::NotReady);
            }

            let mut recv_fgmts = self.state.recv_fgmts_mut();
            let payload = {
                let buf_length = recv_fgmts.iter()
                    .fold(frame_len, |len, f| len + f.payload.len());

                let mut buf = BytesMut::with_capacity(buf_length);
                for buf_frame in recv_fgmts.drain(..) {
                    buf.put(buf_frame.payload);
                }
                buf.put(frame.payload);

                buf
            };

            Ok(Async::Ready(Some(Frame {
                is_finished: true,
                opcode: opcode,
                payload: payload,
                rsv1: rsv1,
                rsv2: rsv2,
                rsv3: rsv3
            })))
        } else {
            match frame.opcode {
                OpCode::Close => {
                    let io = self.state.into_io();
                    let fut = io.send(frame)
                        .map(|_| ())
                        .map_err(|e| Error::new(ErrorKind::ConnectionReset, e));

                    self.state = Some(State::Closing(Box::new(fut)));

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

impl<T: Debug> Debug for State<T> {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match *self {
            State::Open(ref io, ref fgmts, ref rem) => {
                fmt.debug_tuple("Open")
                    .field(io)
                    .field(fgmts)
                    .field(rem)
                    .finish()
            },
            State::Closing(_) |
            State::Closed => {
                fmt.debug_tuple("Closing")
                    .finish()
            }
        }
    }
}

impl<T> TransportState<T> for Option<State<T>> {
    fn into_io(&mut self) -> T {
        match self.take() {
            Some(State::Open(io, _, _)) => io,
            Some(_) => panic!(OP_ON_CLOSED_TP),
            _ => panic!(MISSING_STATE)
        }
    }

    fn io_mut(&mut self) -> &mut T {
        match *self {
            Some(State::Open(ref mut io, _, _)) => io,
            Some(_) => panic!(OP_ON_CLOSED_TP),
            _ => panic!(MISSING_STATE)
        }
    }

    fn recv_fgmts(&self) -> &[Frame] {
        match *self {
            Some(State::Open(_, ref fgmts, _)) => fgmts,
            Some(_) => panic!(OP_ON_CLOSED_TP),
            _ => panic!(MISSING_STATE)
        }
    }

    fn recv_fgmts_mut(&mut self) -> &mut Vec<Frame> {
        match *self {
            Some(State::Open(_, ref mut fgmts, _)) => fgmts,
            Some(_) => panic!(OP_ON_CLOSED_TP),
            _ => panic!(MISSING_STATE)
        }
    }

    fn remaining_mut(&mut self) -> &mut Remaining {
        match *self {
            Some(State::Open(_, _, ref mut rem)) => rem,
            Some(_) => panic!(OP_ON_CLOSED_TP),
            _ => panic!(MISSING_STATE)
        }
    }
}
