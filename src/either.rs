use futures::{try_ready, Async, Future};
use std::result::Result;

pub enum Either2<A, B> {
    A(A),
    B(B),
}

impl<A, B> Future for Either2<A, B>
where
    A: Future,
    B: Future<Error = A::Error>,
{
    type Item = Either2<A::Item, B::Item>;
    type Error = A::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        match self {
            Either2::A(f) => Ok(Either2::A(try_ready!(f.poll())).into()),
            Either2::B(f) => Ok(Either2::B(try_ready!(f.poll())).into()),
        }
    }
}

impl<T> Either2<T, T> {
    pub fn into_inner(self) -> T {
        match self {
            Either2::A(r) | Either2::B(r) => r,
        }
    }
}

pub enum Either3<A, B, C> {
    A(A),
    B(B),
    C(C),
}

impl<A, B, C> Future for Either3<A, B, C>
where
    A: Future,
    B: Future<Error = A::Error>,
    C: Future<Error = A::Error>,
{
    type Item = Either3<A::Item, B::Item, C::Item>;
    type Error = A::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        match self {
            Either3::A(f) => Ok(Either3::A(try_ready!(f.poll())).into()),
            Either3::B(f) => Ok(Either3::B(try_ready!(f.poll())).into()),
            Either3::C(f) => Ok(Either3::C(try_ready!(f.poll())).into()),
        }
    }
}

impl<T> Either3<T, T, T> {
    pub fn into_inner(self) -> T {
        match self {
            Either3::A(r) | Either3::B(r) | Either3::C(r) => r,
        }
    }
}

pub enum Either4<A, B, C, D> {
    A(A),
    B(B),
    C(C),
    D(D),
}

impl<A, B, C, D> Future for Either4<A, B, C, D>
where
    A: Future,
    B: Future<Error = A::Error>,
    C: Future<Error = A::Error>,
    D: Future<Error = A::Error>,
{
    type Item = Either4<A::Item, B::Item, C::Item, D::Item>;
    type Error = A::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        match self {
            Either4::A(f) => Ok(Either4::A(try_ready!(f.poll())).into()),
            Either4::B(f) => Ok(Either4::B(try_ready!(f.poll())).into()),
            Either4::C(f) => Ok(Either4::C(try_ready!(f.poll())).into()),
            Either4::D(f) => Ok(Either4::D(try_ready!(f.poll())).into()),
        }
    }
}

impl<T> Either4<T, T, T, T> {
    pub fn into_inner(self) -> T {
        match self {
            Either4::A(r) | Either4::B(r) | Either4::C(r) | Either4::D(r) => r,
        }
    }
}

pub enum Either6<A, B, C, D, E, F> {
    A(A),
    B(B),
    C(C),
    D(D),
    E(E),
    F(F),
}

impl<A, B, C, D, E, F> Future for Either6<A, B, C, D, E, F>
where
    A: Future,
    B: Future<Error = A::Error>,
    C: Future<Error = A::Error>,
    D: Future<Error = A::Error>,
    E: Future<Error = A::Error>,
    F: Future<Error = A::Error>,
{
    type Item = Either6<A::Item, B::Item, C::Item, D::Item, E::Item, F::Item>;
    type Error = A::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        match self {
            Either6::A(f) => Ok(Either6::A(try_ready!(f.poll())).into()),
            Either6::B(f) => Ok(Either6::B(try_ready!(f.poll())).into()),
            Either6::C(f) => Ok(Either6::C(try_ready!(f.poll())).into()),
            Either6::D(f) => Ok(Either6::D(try_ready!(f.poll())).into()),
            Either6::E(f) => Ok(Either6::E(try_ready!(f.poll())).into()),
            Either6::F(f) => Ok(Either6::F(try_ready!(f.poll())).into()),
        }
    }
}

impl<T> Either6<T, T, T, T, T, T> {
    pub fn into_inner(self) -> T {
        match self {
            Either6::A(r)
            | Either6::B(r)
            | Either6::C(r)
            | Either6::D(r)
            | Either6::E(r)
            | Either6::F(r) => r,
        }
    }
}
