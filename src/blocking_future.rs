use futures::{Async, Future, Poll};
use std::result::Result;
use tokio_threadpool;

pub struct BlockingFuture<F, T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    f: Option<F>,
}

impl<F, T, E> BlockingFuture<F, T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    pub fn new(f: F) -> Self {
        Self { f: Some(f) }
    }
}

impl<F, T, E> Future for BlockingFuture<F, T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    type Item = T;
    type Error = E;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let f = || (self.f.take().expect("future already completed"))();

        match tokio_threadpool::blocking(f) {
            Ok(Async::Ready(Ok(v))) => Ok(Async::Ready(v)),
            Ok(Async::Ready(Err(err))) => Err(err),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            _ => panic!("`BlockingFuture` must be used from the context of the Tokio runtime."),
        }
    }
}
