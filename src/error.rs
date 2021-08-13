use std::error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::AddrParseError;
use std::path::{PathBuf, StripPrefixError};

use axum::body::HttpBody;
use axum::response::IntoResponse;
use http::{Response, StatusCode};
use hyper::Body;
use scrypt::password_hash;

#[derive(Debug)]
pub enum Error {
    InvalidFilename {
        path: PathBuf,
    },
    Io {
        cause: io::Error,
        path: Option<PathBuf>,
    },
    Walkdir {
        cause: walkdir::Error,
    },
    StripPrefix {
        cause: StripPrefixError,
        path: PathBuf,
        base: PathBuf,
    },
    AddrParse {
        cause: AddrParseError,
        addr: String,
    },
    Rusqlite {
        cause: rusqlite::Error,
    },
    Horrorshow {
        cause: horrorshow::Error,
    },
    Hyper {
        cause: hyper::Error,
    },
    R2d2 {
        cause: r2d2::Error,
    },
    Rand {
        cause: rand_core::Error,
    },
    Hash {
        cause: password_hash::Error,
    },
    StreamCancelled,
    InvalidArgument,
    ShareNotFound,
}

impl Error {
    pub fn invalid_filename(path: PathBuf) -> Self {
        Error::InvalidFilename { path }
    }

    pub fn from_io(cause: io::Error, path: PathBuf) -> Self {
        Error::Io {
            cause,
            path: Some(path),
        }
    }

    pub fn from_strip_prefix(cause: StripPrefixError, path: PathBuf, base: PathBuf) -> Self {
        Error::StripPrefix { cause, path, base }
    }

    pub fn from_addr_parse(cause: AddrParseError, addr: String) -> Self {
        Error::AddrParse { cause, addr }
    }
}

impl From<io::Error> for Error {
    fn from(cause: io::Error) -> Self {
        Error::Io { cause, path: None }
    }
}

impl From<walkdir::Error> for Error {
    fn from(cause: walkdir::Error) -> Self {
        Error::Walkdir { cause }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(cause: rusqlite::Error) -> Self {
        Error::Rusqlite { cause }
    }
}

impl From<horrorshow::Error> for Error {
    fn from(cause: horrorshow::Error) -> Self {
        Self::Horrorshow { cause }
    }
}

impl From<hyper::Error> for Error {
    fn from(cause: hyper::Error) -> Self {
        Error::Hyper { cause }
    }
}

impl From<r2d2::Error> for Error {
    fn from(cause: r2d2::Error) -> Self {
        Error::R2d2 { cause }
    }
}

impl From<rand_core::Error> for Error {
    fn from(cause: rand_core::Error) -> Self {
        Error::Rand { cause }
    }
}

impl From<password_hash::Error> for Error {
    fn from(cause: password_hash::Error) -> Self {
        Self::Hash { cause }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidFilename { path } => write!(f, "invalid filename {}", path.display()),
            Error::Io { cause, path: None } => cause.fmt(f),
            Error::Io {
                cause,
                path: Some(path),
            } => write!(f, "{} for path {}", cause, path.display()),
            Error::Walkdir { cause } => cause.fmt(f),
            Error::StripPrefix { cause, path, base } => write!(
                f,
                "{} for path {} and base {}",
                cause,
                path.display(),
                base.display(),
            ),
            Error::AddrParse { cause, addr } => write!(f, "{} for address {}", cause, addr),
            Error::Rusqlite { cause } => cause.fmt(f),
            Error::Horrorshow { cause } => cause.fmt(f),
            Error::Hyper { cause } => cause.fmt(f),
            Error::R2d2 { cause } => cause.fmt(f),
            Error::Rand { cause } => cause.fmt(f),
            Error::Hash { cause } => cause.fmt(f),
            Error::StreamCancelled => write!(f, "the archiving stream was cancelled unexpectedly"),
            Error::InvalidArgument => write!(f, "invalid argument"),
            Error::ShareNotFound => write!(f, "share not found"),
        }
    }
}

impl error::Error for Error {}

impl IntoResponse for Error {
    type Body = hyper::Body;
    type BodyError = <Self::Body as HttpBody>::Error;

    fn into_response(self) -> Response<Body> {
        match self {
            Error::ShareNotFound => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .unwrap(),
            _ => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap(),
        }
    }
}
