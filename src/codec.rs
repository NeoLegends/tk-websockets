use std::io::{Error, ErrorKind};

use bytes::{BufMut, BytesMut};
use nom::IResult;
use tokio_io::codec::{Encoder, Decoder};

use message::Frame;

/// The object resposible for converting `Frame`s into their
/// wire representation and back.
#[derive(Copy, Clone, Debug)]
pub struct Codec {
    is_client: bool,
    max_size: usize,
}

impl Codec {
    /// Initializes a new Encoder.
    ///
    /// # Parameters
    /// - `is_client` determines whether the encoded frames are sent from a client
    /// perspective and thus need to be masked.
    /// - `max_size` determines the maximum packet length before decoding is aborted.
    ///
    /// # Panics
    /// Panics if `max_size` is 0.
    pub fn new(is_client: bool, max_size: usize) -> Self {
        assert!(max_size > 0);

        Codec {
            is_client: is_client,
            max_size: max_size
        }
    }
}

impl Decoder for Codec {
    type Item = Frame;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.len() < 2 {
            // We need at least two bytes for the header.
            return Ok(None);
        }

        let (bytes_consumed, frame) = match Frame::parse(buf.as_ref(), self.max_size) {
            IResult::Done(rest, frame) => (buf.len() - rest.len(), frame),
            IResult::Error(err) => return Err(Error::new(ErrorKind::InvalidData, err)),
            IResult::Incomplete(_) => return Ok(None)
        };

        buf.split_to(bytes_consumed);
        Ok(Some(frame))
    }
}

impl Encoder for Codec {
    type Item = Frame;
    type Error = Error;

    fn encode(&mut self, msg: Self::Item, buf: &mut BytesMut) -> Result<(), Self::Error> {
        msg.write(&mut buf.by_ref().writer(), self.is_client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::usize;

    use bytes::BytesMut;

    #[test]
    fn write() {
        let frame = Frame::new_text("Hello World".to_owned());
        let mut buf = BytesMut::from(Vec::with_capacity(128));

        Codec::new(true, usize::MAX).encode(frame, &mut buf).unwrap();

        assert!(buf.len() > 0);
    }

    #[test]
    fn read_write() {
        let frame1 = Frame::new_text("Hello World".to_owned());
        let frame2 = Frame::new_text("Hello World, you are so beautiful!".to_owned());
        let frame3 = Frame::new_text("Hello World, you are absolutely not beautiful!".to_owned());

        let mut codec = Codec::new(true, usize::MAX);
        let mut buf = BytesMut::from(Vec::with_capacity(128));

        codec.encode(frame1.clone(), &mut buf).unwrap();
        codec.encode(frame2.clone(), &mut buf).unwrap();
        codec.encode(frame3.clone(), &mut buf).unwrap();

        assert!(buf.len() > 0);

        let f1 = codec.decode(&mut buf).unwrap().unwrap();
        let f2 = codec.decode(&mut buf).unwrap().unwrap();
        let f3 = codec.decode(&mut buf).unwrap().unwrap();

        assert_eq!(frame1, f1);
        assert_eq!(frame2, f2);
        assert_eq!(frame3, f3);

        assert_eq!(buf.len(), 0);
    }

    #[test]
    #[should_panic]
    fn min_size_zero() {
        Codec::new(true, 0);
    }
}