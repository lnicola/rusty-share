use diesel;
use std::error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::AddrParseError;
use std::path::{PathBuf, StripPrefixError};
use walkdir;

#[derive(Debug)]
pub enum Error {
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
    Diesel {
        cause: diesel::result::Error,
    },
    StreamCancelled,
}

impl Error {
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

impl From<diesel::result::Error> for Error {
    fn from(cause: diesel::result::Error) -> Self {
        Error::Diesel { cause }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
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
            Error::Diesel { cause } => cause.fmt(f),
            Error::StreamCancelled => write!(f, "the archiving stream was cancelled unexpectedly"),
        }
    }
}

impl error::Error for Error {}
