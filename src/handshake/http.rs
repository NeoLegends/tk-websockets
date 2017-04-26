//! A module dedicated to naive HTTP handling.

use std::fmt::{self, Display, Formatter};
use std::io::{BufRead, Error, ErrorKind};
use std::str;

use futures::{Async, Future, Poll};
use httparse::{self, Status};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::{self as tk_io, ReadUntil};

const NEWLINE_BYTE: u8 = b"\n"[0];

#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ParseRequest<T: AsyncRead + AsyncWrite> {
    state: Option<(ReadUntil<T>, Vec<u8>)>,
}

#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct ParseResponse<T: AsyncRead + AsyncWrite> {
    state: Option<(ReadUntil<T>, Vec<u8>)>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Request {
    pub headers: Vec<(String, Vec<u8>)>,
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Response {
    pub code: u16,
    pub headers: Vec<(String, Vec<u8>)>,
}

impl<T: AsyncRead + AsyncWrite + BufRead> ParseRequest<T>
        where T: AsyncRead {
    pub fn new(io: T) -> Self {
        let buf = Vec::with_capacity(384);
        let fut = tk_io::read_until(io, NEWLINE_BYTE, Vec::with_capacity(64));

        ParseRequest {
            state: Some((fut, buf)),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + BufRead> ParseResponse<T>
        where T: AsyncRead {
    pub fn new(io: T) -> Self {
        let buf = Vec::with_capacity(384);
        let fut = tk_io::read_until(io, NEWLINE_BYTE, Vec::with_capacity(64));

        ParseResponse {
            state: Some((fut, buf)),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + BufRead> Future for ParseRequest<T>
        where T: AsyncRead {
    type Item = (T, Request);
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let (mut fut, mut buf) = self.state.take().expect("cannot poll ParseRequest twice");
            let (io, mut read_buf) = match fut.poll() {
                Ok(Async::Ready(v)) => v,
                Ok(Async::NotReady) => {
                    self.state = Some((fut, buf));
                    return Ok(Async::NotReady);
                },
                Err(e) => return Err(e)
            };

            buf.extend(&read_buf);
            read_buf.clear();

            // Double parse to make borrowck happy :(
            // TODO: Fix this.
            let result = {
                let mut headers = [httparse::EMPTY_HEADER; 32];
                let mut res = httparse::Request::new(&mut headers);
                res.parse(&buf)
            };

            match result {
                Ok(Status::Complete(_)) => {
                    let mut headers = [httparse::EMPTY_HEADER; 32];
                    let mut req = httparse::Request::new(&mut headers);
                    req.parse(&buf).unwrap().unwrap();

                    let req = Request {
                        headers: req.headers.iter()
                            .map(|h| (h.name.to_owned(), h.value.to_owned()))
                            .collect(),
                        method: req.method.expect("missing method").to_owned(),
                        path: req.path.expect("missing path").to_owned()
                    };

                    return Ok(Async::Ready((io, req)));
                }

                Ok(Status::Partial) => {
                    let fut = tk_io::read_until(io, NEWLINE_BYTE, read_buf);
                    self.state = Some((fut, buf));
                }

                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e))
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + BufRead> Future for ParseResponse<T>
        where T: AsyncRead {
    type Item = (T, Response);
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let (mut fut, mut buf) = self.state.take().expect("cannot poll ParseResponse twice");
            let (io, mut read_buf) = match fut.poll() {
                Ok(Async::Ready(v)) => v,
                Ok(Async::NotReady) => {
                    self.state = Some((fut, buf));
                    return Ok(Async::NotReady);
                },
                Err(e) => return Err(e)
            };

            buf.extend(&read_buf);
            read_buf.clear();

            // Double parse to make borrowck happy :(
            // TODO: Fix this.
            let result = {
                let mut headers = [httparse::EMPTY_HEADER; 32];
                let mut res = httparse::Response::new(&mut headers);
                res.parse(&buf)
            };

            match result {
                Ok(Status::Complete(_)) => {
                    let mut headers = [httparse::EMPTY_HEADER; 32];
                    let mut res = httparse::Response::new(&mut headers);
                    res.parse(&buf).unwrap().unwrap();

                    let res = Response {
                        code: res.code.expect("missing response code"),
                        headers: res.headers.iter()
                            .map(|h| (h.name.to_owned(), h.value.to_owned()))
                            .collect()
                    };

                    return Ok(Async::Ready((io, res)));
                }

                Ok(Status::Partial) => {
                    let fut = tk_io::read_until(io, NEWLINE_BYTE, read_buf);
                    self.state = Some((fut, buf));
                }

                Err(e) => return Err(Error::new(ErrorKind::InvalidData, e))
            }
        }
    }
}

impl Request {
    pub fn add_header(&mut self, name: &str, val: String) {
        self.headers.push((name.to_owned(), val.into_bytes()));
    }
}

impl Response {
    pub fn add_header(&mut self, name: &str, val: String) {
        self.headers.push((name.to_owned(), val.into_bytes()));
    }

    fn reason_phrase(&self) -> &str {
        match self.code {
            0...99 => panic!("Invalid HTTP status code"),
            100 => "Continue",
            101 => "Switching Protocols",
            200 => "Ok",
            400 => "Bad Request",
            500 => "Internal Server Error",
            _ => "Unknown"
        }
    }
}

impl Display for Request {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(fmt, "{} {} HTTP/1.1\r\n", self.method, self.path)?;
        for &(ref name, ref val) in self.headers.iter() {
            if let Some(val) = str::from_utf8(&val).ok() {
                write!(fmt, "{}: {}\r\n", name, val)?;
            }
        }
        write!(fmt, "\r\n")
    }
}

impl Display for Response {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(fmt, "HTTP/1.1 {} {}\r\n", self.code, self.reason_phrase())?;
        for &(ref name, ref val) in self.headers.iter() {
            if let Some(val) = str::from_utf8(&val).ok() {
                write!(fmt, "{}: {}\r\n", name, val)?;
            }
        }
        write!(fmt, "\r\n")
    }
}
