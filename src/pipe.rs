use bytes::{Bytes, BytesMut};
use std::io::{Error, ErrorKind, Result, Write};
use tokio::sync::mpsc::Sender;

pub struct Pipe {
    dest: Sender<Bytes>,
    bytes: BytesMut,
}

impl Pipe {
    pub fn new(destination: Sender<Bytes>) -> Self {
        Pipe {
            dest: destination,
            bytes: BytesMut::new(),
        }
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.bytes.extend_from_slice(buf);
        match futures_executor::block_on(self.dest.send(self.bytes.split().freeze())) {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(Error::new(ErrorKind::UnexpectedEof, e)),
        }
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
