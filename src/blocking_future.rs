use futures::{Async, Future, Poll};
use std::convert::Infallible;
use std::result::Result;
use tokio_threadpool;

pub struct BlockingFuture<F, T>
where
    F: FnOnce() -> T,
{
    f: Option<F>,
}

impl<F, T> BlockingFuture<F, T>
where
    F: FnOnce() -> T,
{
    pub fn new(f: F) -> Self {
        Self { f: Some(f) }
    }
}

impl<F, T> Future for BlockingFuture<F, T>
where
    F: FnOnce() -> T,
{
    type Item = T;
    type Error = Infallible;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let f = || (self.f.take().expect("future already completed"))();

        match tokio_threadpool::blocking(f) {
            Ok(r) => Ok(r),
            _ => panic!("`BlockingFuture` must be used from the context of the Tokio runtime."),
        }
    }
}

pub struct BlockingFutureTry<F, T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    f: Option<F>,
}

impl<F, T, E> BlockingFutureTry<F, T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    pub fn new(f: F) -> Self {
        Self { f: Some(f) }
    }
}

impl<F, T, E> Future for BlockingFutureTry<F, T, E>
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
            _ => panic!("`BlockingFutureTry` must be used from the context of the Tokio runtime."),
        }
    }
}
