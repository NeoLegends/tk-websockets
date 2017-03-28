use std::io::{Error, ErrorKind, Write};
use std::str::{self, Utf8Error};
use std::u16;

use bytes::{BigEndian, Buf, BufMut, BytesMut, IntoBuf};
use nom::{self, IResult};
use rand;

/// The maximum size of a websocket control frame.
///
/// Frames larger than this cannot be sent and trigger an error
/// when received.
pub const MAX_CONTROL_FRAME_SIZE: usize = 125;

/// The error message when the payload of a control frame
/// is too large.
///
/// The payload size of a WebSocket control frame must
/// - by definition - not exceed 125 bytes.
const CONTROL_FRAME_PAYLOAD_TOO_LONG: &'static str = "Contents of control frames must not be longer than 125 bytes.";

/// Computes the smaller one of two values.
#[macro_use]
macro_rules! min {
    ($a:expr, $b:expr) => ({
        let a = $a;
        let b = $b;
        if a > b {
            b
        } else {
            a
        }
    })
}

/// Applies the given websocket mask to the given data.
fn apply_mask(data: &mut [u8], mask: &[u8]) {
    assert!(mask.len() == 4);

    let zipped = data.iter_mut().zip(mask.iter().cycle());
    for (byte, &mask) in zipped {
        *byte ^= mask;
    }
}

/// Parses a Frame from the given slice.
fn parse_frame(data: &[u8], max_frame_size: usize) -> IResult<&[u8], Frame> {
    do_parse!(data,
        header: parse_frame_header >>
        mask: cond!(header.5, take!(4)) >>
        payload: call!(parse_content, header.4, header.6, max_frame_size) >>

        (Frame {
            is_finished: header.0,
            opcode: header.4,
            payload: {
                let mut p: BytesMut = payload.to_owned().into();
                if let Some(mask) = mask {
                    apply_mask(&mut p, mask);
                }
                p
            },
            rsv1: header.1,
            rsv2: header.2,
            rsv3: header.3
        })
    )
}

/// Parses the frame's content.
fn parse_content(data: &[u8], op: OpCode, length: u64, max_frame_size: usize)
        -> IResult<&[u8], &[u8]> {
    if op.is_control() && length as usize > MAX_CONTROL_FRAME_SIZE {
        return IResult::Error(nom::ErrorKind::Count);
    }
    if length as usize > max_frame_size {
        return IResult::Error(nom::ErrorKind::Count);
    }

    take!(data, length)
}

/// Parses a the header part of a frame from a given slice.
///
/// This is an internal function used by `parse_frame`. Do not use this directly.
named!(parse_frame_header<&[u8], (bool, bool, bool, bool, OpCode, bool, u64)>,
    bits!(do_parse!(
        finished: take_bits!(u8, 1) >>
        rsv1: take_bits!(u8, 1) >>
        rsv2: take_bits!(u8, 1) >>
        rsv3: take_bits!(u8, 1) >>
        opcode: map_res!(take_bits!(u8, 4), OpCode::parse) >>
        has_mask: take_bits!(u8, 1) >>
        payload_length: switch!(take_bits!(u64, 7),
            v @ 0...125 => value!(v) |
            126 => take_bits!(u64, 16) |
            127 => take_bits!(u64, 64)
        ) >>

        (
            finished != 0,
            rsv1 != 0,
            rsv2 != 0,
            rsv3 != 0,
            opcode,
            has_mask != 0,
            payload_length
        )
    ))
);

/// The reason for closing the connection.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum CloseCode {
    /// Indicates a normal closure, meaning that the purpose for
    /// which the connection was established has been fulfilled.
    Normal,

    /// Indicates that an endpoint is "going away", such as a server
    /// going down or a browser having navigated away from a page.
    Away,

    /// Indicates that an endpoint is terminating the connection due
    /// to a protocol error.
    Protocol,

    /// Indicates that an endpoint is terminating the connection
    /// because it has received a type of data it cannot accept (e.g., an
    /// endpoint that understands only text data MAY send this if it
    /// receives a binary message).
    Unsupported,

    /// Indicates that no status code was included in a closing frame. This
    /// close code makes it possible to use a single method, `on_close` to
    /// handle even cases where no close code was provided.
    Status,

    /// Indicates an abnormal closure. If the abnormal closure was due to an
    /// error, this close code will not be used. Instead, the `on_error` method
    /// of the handler will be called with the error. However, if the connection
    /// is simply dropped, without an error, this close code will be sent to the
    /// handler.
    Abnormal,

    /// Indicates that an endpoint is terminating the connection
    /// because it has received data within a message that was not
    /// consistent with the type of the message (e.g., non-UTF-8 [RFC3629]
    /// data within a text message).
    Invalid,

    /// Indicates that an endpoint is terminating the connection
    /// because it has received a message that violates its policy.  This
    /// is a generic status code that can be returned when there is no
    /// other more suitable status code (e.g., Unsupported or Size) or if there
    /// is a need to hide specific details about the policy.
    Policy,

    /// Indicates that an endpoint is terminating the connection
    /// because it has received a message that is too big for it to
    /// process.
    Size,

    /// Indicates that an endpoint (client) is terminating the
    /// connection because it has expected the server to negotiate one or
    /// more extension, but the server didn't return them in the response
    /// message of the WebSocket handshake.  The list of extensions that
    /// are needed should be given as the reason for closing.
    /// Note that this status code is not used by the server, because it
    /// can fail the WebSocket handshake instead.
    Extension,

    /// Indicates that a server is terminating the connection because
    /// it encountered an unexpected condition that prevented it from
    /// fulfilling the request.
    Error,

    /// Indicates that the server is restarting. A client may choose to reconnect,
    /// and if it does, it should use a randomized delay of 5-30 seconds between attempts.
    Restart,

    /// Indicates that the server is overloaded and the client should either connect
    /// to a different IP (when multiple targets exist), or reconnect to the same IP
    /// when a user has performed an action.
    Again,

    #[doc(hidden)]
    Tls,

    /// Close codes in the range of 3000-3999 for application usage.
    ///
    /// These close codes are registered with IANA and thus not freely available.
    IanaReserved(u16),

    /// Close codes in the range of 4000-4999 that are reserved for application usage.
    ///
    /// These close codes are not registered and thus are left for the application
    /// to deal with.
    Other(u16),
}

/// An iterator yields correctly formatted fragments of the given `Frame`.
///
/// Created by calling `Frame::fragment(size)`.
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Fragments {
    // optimized field order
    frame: Option<Frame>,
    size: usize,
    first: bool,
}

/// A websocket frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    // This sits up here for better alignment. Compresses the struct down to
    // 32 bytes instead of 40. Once struct field reordering is stable this will
    // not be necessary anymore and the fields can be ordered alphabetically.

    /// The payload.
    ///
    /// The payload is automatically unmasked during parsing and will
    /// automatically be masked during encoding. Do not do the masking
    /// yourself.
    pub payload: BytesMut,

    /// Indicates whether the frame is finished.
    ///
    /// Websocket messages may be split up into multiple frames. If that
    /// is the case, this is set to false.
    pub is_finished: bool,

    /// The frame's opcode.
    pub opcode: OpCode,

    /// The first reserved bit.
    ///
    /// This bit is reserved for usage by websocket extensions. They must
    /// not be used from an application context.
    pub rsv1: bool,

    /// The second reserved bit.
    ///
    /// This bit is reserved for usage by websocket extensions. They must
    /// not be used from an application context.
    pub rsv2: bool,

    /// The third reserved bit.
    ///
    /// This bit is reserved for usage by websocket extensions. They must
    /// not be used from an application context.
    pub rsv3: bool,
}

/// A websocket message. Can either be textual or binary data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    /// A message containing binary data.
    Binary(Vec<u8>),

    /// A message containing text data.
    Text(String)
}

/// The frame opcode.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum OpCode {
    /// The frame is a continuation frame.
    Continue,

    /// The frame is a text frame and contains UTF-8 encoded text.
    Text,

    /// The frame is a binary frame and contains arbitrary binary data.
    Binary,

    /// The frame is a closing frame.
    Close,

    /// The frame is a ping frame.
    Ping,

    /// The frame is a pong frame.
    Pong,
}

impl CloseCode {
    /// Attempts to parse a CloseCode from the given value.
    pub fn parse(value: u16) -> Result<CloseCode, Error> {
        use self::CloseCode::*;

        match value {
            0...999 => Err(::std::io::Error::new(ErrorKind::InvalidData, "Close code in the unused range 0-999.")),
            1000 => Ok(Normal),
            1001 => Ok(Away),
            1002 => Ok(Protocol),
            1003 => Ok(Unsupported),
            1005 => Ok(Status),
            1006 => Ok(Abnormal),
            1007 => Ok(Invalid),
            1008 => Ok(Policy),
            1009 => Ok(Size),
            1010 => Ok(Extension),
            1011 => Ok(Error),
            1012 => Ok(Restart),
            1013 => Ok(Again),
            1015 => Ok(Tls),
            3000...3999 => Ok(IanaReserved(value)),
            4000...4999 => Ok(Other(value)),
            _ => Err(::std::io::Error::new(ErrorKind::InvalidData, "Unknown close code value.")),
        }
    }
}

impl Fragments {
    /// Creates a new `Fragments` iterator.
    ///
    /// # Panics
    /// Panics when `size == 0` and `!payload.is_empty()` at the same time.
    fn new(frame: Frame, size: usize) -> Fragments {
        assert!(frame.payload.is_empty() || size > 0);

        Fragments {
            first: true,
            frame: Some(frame),
            size: size
        }
    }
}

impl Iterator for Fragments {
    type Item = Frame;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(mut frame) = self.frame.take() {
            // Optimize for the case where the frame is smaller than the given size
            if frame.payload.len() <= self.size && self.first {
                return Some(frame);
            }

            let at = min!(self.size, frame.payload.len());
            let rest = frame.payload.split_off(at);
            let has_next = rest.len() > 0;

            if self.first {
                self.first = false;

                self.frame = Some(Frame {
                    payload: rest,
                    ..Default::default()
                });
                let res =  Some(Frame {
                    is_finished: false,
                    opcode: frame.opcode,
                    payload: frame.payload,
                    rsv1: frame.rsv1,
                    rsv2: frame.rsv2,
                    rsv3: frame.rsv3
                });
                res
            } else if has_next {
                self.frame = Some(Frame {
                    payload: rest,
                    ..Default::default()
                });

                Some(Frame {
                    is_finished: false,
                    opcode: OpCode::Continue,
                    payload: frame.payload,
                    ..Default::default()
                })
            } else {
                Some(Frame {
                    is_finished: true,
                    opcode: OpCode::Continue,
                    payload: frame.payload,
                    ..Default::default()
                })
            }
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.frame
            .as_ref()
            .map(|f| (f.payload.len() as f64 / self.size as f64).ceil() as usize)
            .unwrap_or(0);

        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Fragments { }

impl Frame {
    /// Creates a new Frame with binary data.
    pub fn new_binary(data: Vec<u8>) -> Self {
        Frame {
            opcode: OpCode::Binary,
            payload: data.into(),
            ..Default::default()
        }
    }

    /// Creates a new closing Frame.
    pub fn new_close() -> Self {
        Frame {
            opcode: OpCode::Close,
            ..Default::default()
        }
    }

    /// Creates a new closing Frame with a reason.
    ///
    /// # Panics
    /// Panics if the length of the reason string (in bytes) is > 123.
    pub fn new_close_with_reason(code: CloseCode, reason: &str) -> Self {
        assert!((reason.as_bytes().len() + 2) <= MAX_CONTROL_FRAME_SIZE, CONTROL_FRAME_PAYLOAD_TOO_LONG);

        let mut payload = BytesMut::with_capacity(reason.len() + 2);

        payload.put_u16::<BigEndian>(code.into());
        payload.put_slice(reason.as_bytes());

        Frame {
            opcode: OpCode::Close,
            payload: payload,
            ..Default::default()
        }
    }

    /// Creates a new ping Frame.
    ///
    /// # Panics
    /// Panics if more than 125 bytes of `data` are given.
    pub fn new_ping(data: Vec<u8>) -> Self {
        assert!(data.len() <= MAX_CONTROL_FRAME_SIZE, CONTROL_FRAME_PAYLOAD_TOO_LONG);

        Frame {
            opcode: OpCode::Ping,
            payload: data.into(),
            ..Default::default()
        }
    }


    /// Creates a new pong Frame.
    ///
    /// # Panics
    /// Panics if more than 125 bytes of `data` are given.
    pub fn new_pong(data: Vec<u8>) -> Self {
        assert!(data.len() <= MAX_CONTROL_FRAME_SIZE, CONTROL_FRAME_PAYLOAD_TOO_LONG);

        Frame {
            opcode: OpCode::Pong,
            payload: data.into(),
            ..Default::default()
        }
    }

    /// Creates a new textual frame.
    pub fn new_text(data: String) -> Self {
        Frame {
            opcode: OpCode::Text,
            payload: data.into_bytes().into(),
            ..Default::default()
        }
    }

    /// Attempts to parse a Frame from the given data.
    pub fn parse(data: &[u8], max_frame_size: usize) -> IResult<&[u8], Self> {
        parse_frame(data, max_frame_size)
    }

    /// Computes the length of the Frame in encoded form.
    pub fn len(&self, is_masked: bool) -> usize {
        let mut header_length = 2;
        let payload_len = self.payload().len();
        if payload_len > 125 {
            if payload_len <= u16::max_value() as usize {
                header_length += 2;
            } else {
                header_length += 8;
            }
        }

        if is_masked {
            header_length += 4;
        }

        header_length + payload_len
    }

    /// Fragments the `Frame` into multiple Frames of the given size.
    ///
    /// These frames can then be sent over the websocket connection to the
    /// other side where they can be defragmented to form a single frame again,
    /// while at the same time being able to send control frames in between.
    ///
    /// This is useful for large messages that would otherwise take a long time
    /// to fully transmit. See [the websocket protocol](https://tools.ietf.org/html/rfc6455#section-5.4)
    /// for more information.
    ///
    /// # Panics
    /// Panics when `size == 0` and `!payload.is_empty()` at the same time.
    pub fn fragment(self, size: usize) -> Fragments {
        Fragments::new(self, size)
    }

    /// Gets the payload as slice.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }

    /// Gets the payload as mutable slice.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.payload.as_mut()
    }

    /// Parses a possibly contained `CloseCode` from the `Frame`s contents.
    ///
    /// Note: this only works on packets of type `OpCode::Close`.
    pub fn read_close_code(&self) -> Option<CloseCode> {
        if self.payload.len() < 2 {
            return None;
        }

        match self.opcode {
            OpCode::Close => {
                let mut buf = self.payload.as_ref().into_buf();
                CloseCode::parse(buf.get_u16::<BigEndian>()).ok()
            },
            _ => None
        }
    }

    /// Attempts to read the `Frame` content as UTF-8 encoded string.
    pub fn read_utf8(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(self.payload())
    }

    /// Writes the Frame into the given writer.
    ///
    /// Parameter `mask` indicates whether the contents shall be masked.
    /// Masking must occur when the packet is transferred from the client
    /// to the server.
    pub fn write<W: Write>(&self, w: &mut W, mask: bool) -> Result<(), Error> {
        let mut buf = BytesMut::with_capacity(10);
        let mut meta: u8 = 0;
        if self.is_finished {
            meta |= 0b1000_0000;
        }
        if self.rsv1 {
            meta |= 0b100_0000;
        }
        if self.rsv2 {
            meta |= 0b10_0000;
        }
        if self.rsv3 {
            meta |= 0b1_0000;
        }
        meta |= self.opcode.into();

        buf.put_u8(meta);
        meta = 0;

        if mask {
            meta |= 0b1000_0000;
        }

        let (len, extra_len) = if self.payload.len() < 126 {
            (self.payload.len() as u8, None)
        } else if self.payload.len() <= (u16::MAX as usize) {
            (126, Some(self.payload.len()))
        } else {
            (127, Some(self.payload.len()))
        };

        meta |= len;
        buf.put_u8(meta);

        if let Some(extra_len) = extra_len {
            if extra_len <= (u16::MAX as usize) {
                buf.put_u16::<BigEndian>(extra_len as u16);
            } else {
                buf.put_u64::<BigEndian>(extra_len as u64);
            }
        }

        w.write_all(&buf)?;

        if mask {
            // We'd like to keep the &self bound for ::write. This means we need to
            // allocate here, since we cannot modify the internal buffer to apply
            // the masking.
            //
            // To optimize the process a little and in order to avoid allocating
            // excessive amounts of memory, we're using a 8kb temporary buffer.
            //
            // 8kb is also what the stdlib uses in terms of temporary buffer sizes.

            const BUFFER_SIZE: usize = 8 * 1024;

            let mask: [u8; 4] = rand::random();
            w.write_all(&mask)?;

            // Don't overallocate
            let capacity = min!(self.payload.len(), BUFFER_SIZE);
            let mut buf = Vec::with_capacity(capacity);

            // Since were &self, we could try to use something like rayon here...
            for ch in (&self.payload[..]).chunks(capacity) {
                buf.extend_from_slice(ch);

                apply_mask(&mut buf, &mask);
                w.write_all(&buf)?;

                buf.clear();
            }

            Ok(())
        } else {
            w.write_all(&self.payload)
        }
    }
}

impl Default for Frame {
    fn default() -> Self {
        Frame {
            is_finished: true,
            opcode: OpCode::Close,
            payload: Vec::new().into(),
            rsv1: false,
            rsv2: false,
            rsv3: false
        }
    }
}

impl From<CloseCode> for Frame {
    fn from(code: CloseCode) -> Self {
        Frame::new_close_with_reason(code, "")
    }
}

impl From<Message> for Frame {
    fn from(msg: Message) -> Self {
        match msg {
            Message::Binary(data) => Frame::new_binary(data),
            Message::Text(t) => Frame::new_text(t)
        }
    }
}

impl OpCode {
    /// Parses an OpCode from the given value.
    pub fn parse(value: u8) -> Result<OpCode, Error> {
        use self::OpCode::*;

        match value {
            0x0 => Ok(Continue),
            0x1 => Ok(Text),
            0x2 => Ok(Binary),
            0x8 => Ok(Close),
            0x9 => Ok(Ping),
            0xA => Ok(Pong),
            _ => Err(Error::new(ErrorKind::InvalidData, "Invalid opcode value."))
        }
    }

    /// Returns whether the OpCode is a control opcode.
    ///
    /// Anything other than `Continue`, `Text` and `Binary` is a control opcode.
    pub fn is_control(&self) -> bool {
        use self::OpCode::*;

        match *self {
            Continue | Text | Binary => false,
            _ => true
        }
    }

    /// Returns whether the OpCode is a data opcode.
    ///
    /// Data opcodes are `Text` and `Binary`.
    pub fn is_data(&self) -> bool {
        use self::OpCode::*;

        match *self {
            Text | Binary => true,
            _ => false
        }
    }
}

impl From<CloseCode> for u16 {
    fn from(code: CloseCode) -> Self {
        use self::CloseCode::*;

        match code {
            Normal => 1000,
            Away => 1001,
            Protocol => 1002,
            Unsupported => 1003,
            Status => 1005,
            Abnormal => 1006,
            Invalid => 1007,
            Policy => 1008,
            Size => 1008,
            Extension => 1010,
            Error => 1011,
            Restart => 1012,
            Again => 1013,
            Tls => 1015,
            IanaReserved(v) | Other(v) => v
        }
    }
}

impl From<OpCode> for u8 {
    fn from(code: OpCode) -> Self {
        use self::OpCode::*;

        match code {
            Continue => 0x0,
            Text => 0x1,
            Binary => 0x2,
            Close => 0x8,
            Ping => 0x9,
            Pong => 0xA
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::usize;

    const PACKET_UNFINISHED: &'static str = "Frame not finished";
    const RSV_INVALID: &'static str = "Reserved bits invalid";
    const UNMASKED: &'static str = "Masked frame unmased";

    #[test]
    fn header_smoke() {
        let data = vec![
            0b1_010_0001, 0b1_0001001
        ];

        let (_, (fin, rsv1, rsv2, rsv3, op, is_masked, len)) =
            parse_frame_header(data.as_ref()).unwrap();

        assert!(fin, PACKET_UNFINISHED);
        assert!(!rsv1 && rsv2 && !rsv3, RSV_INVALID);
        assert_eq!(op, OpCode::Text);
        assert!(is_masked, UNMASKED);
        assert_eq!(len, 9);
    }

    #[test]
    fn header_u16_length() {
        let data = vec![
            0b1_010_0001, 0b1_1111110,
            0, 0b11001000
        ];

        let (_, (fin, rsv1, rsv2, rsv3, op, is_masked, len)) =
            parse_frame_header(data.as_ref()).unwrap();

        assert!(fin, PACKET_UNFINISHED);
        assert!(!rsv1 && rsv2 && !rsv3, RSV_INVALID);
        assert_eq!(op, OpCode::Text);
        assert!(is_masked, UNMASKED);
        assert_eq!(len, 200);
    }

    #[test]
    fn header_u64_length() {
        let data = vec![
            0b1_010_0001, 0b1_1111111,
            0, 0, 0, 0, 0, 1, 0, 1
        ];

        let (_, (fin, rsv1, rsv2, rsv3, op, is_masked, len)) =
            parse_frame_header(data.as_ref()).unwrap();

        assert!(fin, PACKET_UNFINISHED);
        assert!(!rsv1 && rsv2 && !rsv3, RSV_INVALID);
        assert_eq!(op, OpCode::Text);
        assert!(is_masked, UNMASKED);
        assert_eq!(len, 65537);
    }

    #[test]
    fn frame_smoke() {
        let data = vec![
            0b0_111_0010, 0b1_0000001,
            0, 0, 0, 1,
            1
        ];

        let (_, frame) = Frame::parse(data.as_ref(), usize::MAX).unwrap();

        assert!(!frame.is_finished, PACKET_UNFINISHED);
        assert!(frame.rsv1 && frame.rsv2 && frame.rsv3, RSV_INVALID);
        assert_eq!(frame.opcode, OpCode::Binary);
        assert_eq!(frame.payload().len(), 1);
        assert_eq!(frame.payload()[0], 1);
    }

    #[test]
    fn masked() {
        let data = vec![
            0b0_111_0010, 0b1_0000100,
            0, 0, 1, 1,
            1, 0, 0, 0
        ];

        let (_, frame) = Frame::parse(data.as_ref(), usize::MAX).unwrap();

        assert!(!frame.is_finished, PACKET_UNFINISHED);
        assert!(frame.rsv1 && frame.rsv2 && frame.rsv3, RSV_INVALID);
        assert_eq!(frame.opcode, OpCode::Binary);
        assert_eq!(frame.payload().len(), 4);
        assert_eq!(frame.payload(), &[1, 0, 1, 1]);
    }

    #[test]
    fn unmasked() {
        let data = vec![
            0b0_111_0010, 0b0_0000100,
            1, 0, 0, 0
        ];

        let (_, frame) = Frame::parse(data.as_ref(), usize::MAX).unwrap();

        assert!(!frame.is_finished, PACKET_UNFINISHED);
        assert!(frame.rsv1 && frame.rsv2 && frame.rsv3, RSV_INVALID);
        assert_eq!(frame.opcode, OpCode::Binary);
        assert_eq!(frame.payload().len(), 4);
        assert_eq!(frame.payload(), &[1, 0, 0, 0]);
    }

    #[test]
    fn length() {
        let data = vec![0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
        let (_, f) = Frame::parse(data.as_ref(), usize::MAX).unwrap();

        assert_eq!(f.len(false), data.len());

        let data = vec![0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
        let (_, f) = Frame::parse(data.as_ref(), usize::MAX).unwrap();

        assert_eq!(f.len(true), data.len());
    }

    #[test]
    fn rfc_example_1() {
        let data = vec![0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let (_, frame) = Frame::parse(data.as_ref(), usize::MAX).unwrap();

        assert_eq!(frame.opcode, OpCode::Text);
        assert_eq!(frame.read_utf8(), Ok("Hello"));

        let mut buf = Vec::new();
        frame.write(&mut buf, false).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);

        buf.clear();
        frame.write(&mut buf, true).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);
    }

    #[test]
    fn rfc_example_2() {
        let data = vec![0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];

        let (_, frame) = Frame::parse(data.as_ref(), usize::MAX).unwrap();

        assert_eq!(frame.opcode, OpCode::Text);
        assert_eq!(frame.read_utf8(), Ok("Hello"));

        let mut buf = Vec::new();
        frame.write(&mut buf, false).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);

        buf.clear();
        frame.write(&mut buf, true).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);
    }

    #[test]
    fn rfc_example_4() {
        let data = vec![0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];

        let (_, frame) = Frame::parse(data.as_ref(), usize::MAX).unwrap();

        assert_eq!(frame.opcode, OpCode::Ping);

        let mut buf = Vec::new();
        frame.write(&mut buf, false).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);

        buf.clear();
        frame.write(&mut buf, true).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);
    }

    #[test]
    fn write() {
        let frame = Frame {
            is_finished: true,
            rsv1: true,
            rsv2: false,
            rsv3: false,
            opcode: OpCode::Binary,
            payload: vec![0u8, 1, 2, 3, 4, 5].into()
        };

        let mut buf = Vec::new();

        frame.write(&mut buf, false).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);

        buf.clear();

        frame.write(&mut buf, true).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);
    }

    #[test]
    fn write_u16_length() {
        use std::iter::repeat;
        let frame = Frame {
            is_finished: false,
            rsv1: true,
            rsv2: true,
            rsv3: false,
            opcode: OpCode::Binary,
            payload: repeat(0u8).take(8192).collect::<Vec<_>>().into()
        };

        let mut buf = Vec::new();

        frame.write(&mut buf, false).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);

        buf.clear();

        frame.write(&mut buf, true).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);
    }

    #[test]
    fn write_u64_length() {
        use std::iter::repeat;
        let frame = Frame {
            is_finished: true,
            rsv1: true,
            rsv2: false,
            rsv3: true,
            opcode: OpCode::Binary,
            payload: repeat(0u8).take(128000).collect::<Vec<_>>().into()
        };

        let mut buf = Vec::new();

        frame.write(&mut buf, false).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);

        buf.clear();

        frame.write(&mut buf, true).unwrap();
        assert_eq!(frame, Frame::parse(&buf, usize::MAX).unwrap().1);
    }

    #[test]
    fn fragments() {
        let mut frame = Frame::new_binary(vec![0, 0, 1, 1, 2, 2]);
        frame.rsv1 = true;

        let mut fragments = frame.fragment(2);

        let frag1 = fragments.next().expect("Missing fragment 1");
        assert!(frag1.rsv1);
        assert!(!frag1.is_finished);
        assert_eq!(frag1.payload(), &[0, 0]);
        assert_eq!(frag1.opcode, OpCode::Binary);

        let frag2 = fragments.next().expect("Missing fragment 2");
        assert!(!frag2.rsv1);
        assert!(!frag2.is_finished);
        assert_eq!(frag2.payload(), &[1, 1]);
        assert_eq!(frag2.opcode, OpCode::Continue);

        let frag3 = fragments.next().expect("Missing fragment 3");
        assert!(!frag3.rsv1);
        assert!(frag3.is_finished);
        assert_eq!(frag3.payload(), &[2, 2]);
        assert_eq!(frag3.opcode, OpCode::Continue);

        assert!(fragments.next().is_none());
    }

    #[test]
    fn fragments_single() {
        let mut frame = Frame::new_binary(vec![0]);
        frame.rsv1 = true;

        let mut fragments = frame.fragment(1);

        let frag = fragments.next().expect("Missing fragment");
        assert!(frag.rsv1);
        assert!(frag.is_finished);
        assert_eq!(frag.payload(), &[0]);
        assert_eq!(frag.opcode, OpCode::Binary);

        assert!(fragments.next().is_none());
    }

    #[test]
    fn framents_size_hint() {
        let mut fgmts = Frame::new_binary(vec![0, 0, 1, 1, 2, 2, 3]).fragment(2);

        while let Some(_) = fgmts.next() {
            fgmts.len(); // This checks just if our implementation is buggy
        }

        let mut fgmts = Frame::new_binary(vec![0, 0, 1, 1, 2, 2, 3]).fragment(2);
        assert_eq!(fgmts.len(), 4);
        fgmts.next();
        assert_eq!(fgmts.len(), 3);
        fgmts.next();
        assert_eq!(fgmts.len(), 2);
        fgmts.next();
        assert_eq!(fgmts.len(), 1);
        fgmts.next();
        assert_eq!(fgmts.len(), 0);
    }

    #[test]
    fn min_macro() {
        assert_eq!(min!(4, 6), 4);
        assert_eq!(min!(6, 4), 4);
    }
}