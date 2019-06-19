use futures::{try_ready, Async, Future};
use std::result::Result;

macro_rules! replace {
    ($_:tt $sub:tt) => {
        $sub
    };
}

macro_rules! define_either {
    ($name:ident, $first:ident, $($rest:ident),*) => {
        pub enum $name<$first, $($rest),*> {
            $first($first),
            $($rest($rest)),*
        }

        impl<$first, $($rest),*> Future for $name<$first, $($rest),*>
        where
            $first: Future,
            $($rest: Future<Error = $first::Error>),*
        {
            type Item = $name<$first::Item, $($rest::Item),*>;
            type Error = $first::Error;

            fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
                match self {
                    $name::$first(f) => Ok($name::$first(try_ready!(f.poll())).into()),
                    $($name::$rest(f) => Ok($name::$rest(try_ready!(f.poll())).into())),*
                }
            }
        }

        impl<T> $name<T, $(replace!($rest T)),*> {
            pub fn into_inner(self) -> T {
                match self {
                    $name::$first(r) $(| $name::$rest(r))* => r,
                }
            }
        }
    };
}

define_either!(Either2, A, B);
define_either!(Either3, A, B, C);
define_either!(Either4, A, B, C, D);
define_either!(Either6, A, B, C, D, E, F);
