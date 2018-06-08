use bytes::{BufMut, Bytes, BytesMut};
use futures::sink::Wait;
use futures::sync::mpsc::Sender;
use std::io::{Error, ErrorKind, Result, Write};

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

impl Drop for Pipe {
    fn drop(&mut self) {
        let _ = self.dest.close();
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.bytes.reserve(buf.len());
        self.bytes.put(buf);
        match self.dest.send(self.bytes.take().into()) {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(Error::new(ErrorKind::UnexpectedEof, e)),
        }
    }

    fn flush(&mut self) -> Result<()> {
        self.dest
            .flush()
            .map_err(|e| Error::new(ErrorKind::UnexpectedEof, e))
    }
}
