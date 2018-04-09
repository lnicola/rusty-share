use bytes::{BufMut, Bytes, BytesMut};
use futures::sink::Wait;
use futures::sync::mpsc::Sender;
use std::io::{self, ErrorKind, Write};

pub struct Pipe {
    dest: Wait<Sender<Bytes>>,
    bytes: BytesMut,
}

impl Pipe {
    pub fn new(destination: Wait<Sender<Bytes>>) -> Self {
        Pipe {
            dest: destination,
            bytes: BytesMut::new(),
        }
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.reserve(buf.len());
        self.bytes.put(buf);
        match self.dest.send(self.bytes.take().into()) {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(io::Error::new(ErrorKind::UnexpectedEof, e)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.dest.flush() {
            Ok(_) => Ok(()),
            Err(e) => Err(io::Error::new(ErrorKind::UnexpectedEof, e)),
        }
    }
}
