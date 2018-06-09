use futures::{Async, Future, Poll};
use std::fs::{self, Metadata};
use std::io;
use std::path::PathBuf;
use std::result::Result;
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
            Ok(Async::Ready(Ok(v))) => Ok(v.into()),
            Ok(Async::Ready(Err(err))) => Err(err),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => panic!(
                "`blocking` annotated I/O must be called \
                 from the context of the Tokio runtime."
            ),
        }
    }
}

pub fn metadata(path: PathBuf) -> impl Future<Item = Metadata, Error = io::Error> {
    BlockingFuture::new(|| fs::metadata(path))
}
