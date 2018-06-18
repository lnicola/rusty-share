use futures::{try_ready, Async, Future, Poll};
use std::fs::{self, Metadata};
use std::io::{self, ErrorKind, SeekFrom};
use std::path::PathBuf;
use std::result::Result;
use tokio;
use tokio_threadpool;

pub struct BlockingFuture<F, T, E>(Option<F>)
where
    F: FnOnce() -> Result<T, E>;

impl<F, T, E> BlockingFuture<F, T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    pub fn new(f: F) -> Self {
        BlockingFuture::<F, T, E>(Some(f))
    }
}

impl<F, T, E> Future for BlockingFuture<F, T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    type Item = T;
    type Error = E;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let f = self.0.take().expect("future already completed");

        match tokio_threadpool::blocking(f) {
            Ok(Async::Ready(Ok(v))) => Ok(Async::Ready(v)),
            Ok(Async::Ready(Err(err))) => Err(err),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            _ => panic!(
                "`blocking` annotated I/O must be called \
                 from the context of the Tokio runtime."
            ),
        }
    }
}

pub fn metadata(path: PathBuf) -> MetadataFuture {
    MetadataFuture { path }
}

pub struct MetadataFuture {
    path: PathBuf,
}

impl Future for MetadataFuture {
    type Item = Metadata;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        blocking_io(|| fs::metadata(&self.path))
    }
}

pub struct SeekFuture {
    pos: SeekFrom,
    inner: Option<tokio::fs::File>,
}

impl Future for SeekFuture {
    type Item = (tokio::fs::File, u64);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let pos = try_ready!(
            self.inner
                .as_mut()
                .expect("Cannot poll `SeekFuture` after it resolves")
                .poll_seek(self.pos)
        );
        let inner = self.inner.take().unwrap();
        Ok((inner, pos).into())
    }
}

pub trait FileExt: Sized {
    fn seek(self, pos: SeekFrom) -> SeekFuture;
}

impl FileExt for tokio::fs::File {
    fn seek(self, pos: SeekFrom) -> SeekFuture {
        SeekFuture {
            pos,
            inner: Some(self),
        }
    }
}

pub fn blocking_io<F, T>(f: F) -> Poll<T, io::Error>
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
        ErrorKind::Other,
        "`blocking` annotated I/O must be called from the context of the Tokio runtime.",
    )
}
