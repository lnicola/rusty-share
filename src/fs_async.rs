use futures::{Async, Future, Poll};
use std::fs::{self, Metadata};
use std::io;
use std::path::Path;
use tokio_threadpool;

fn blocking_io<F, T>(f: F) -> Poll<T, io::Error>
where
    F: FnOnce() -> io::Result<T>,
{
    match tokio_threadpool::blocking(f) {
        Ok(Async::Ready(Ok(v))) => Ok(v.into()),
        Ok(Async::Ready(Err(err))) => Err(err),
        Ok(Async::NotReady) => Ok(Async::NotReady),
        Err(_) => Err(blocking_err()),
    }
}

pub fn blocking_err() -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        "`blocking` annotated I/O must be called \
         from the context of the Tokio runtime.",
    )
}

#[derive(Debug)]
pub struct MetadataFuture<P> {
    path: P,
}

impl<P> MetadataFuture<P>
where
    P: AsRef<Path> + Send + 'static,
{
    pub(crate) fn new(path: P) -> Self {
        MetadataFuture { path }
    }
}

impl<P> Future for MetadataFuture<P>
where
    P: AsRef<Path> + Send + 'static,
{
    type Item = Metadata;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        blocking_io(|| fs::metadata(&self.path))
    }
}

pub fn metadata<P>(path: P) -> MetadataFuture<P>
where
    P: AsRef<Path> + Send + 'static,
{
    MetadataFuture::new(path)
}
