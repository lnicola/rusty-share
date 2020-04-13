use os_str_bytes::OsStringBytes;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef};
use rusqlite::{Error, Row, ToSql};
use std::ffi::OsString;
use std::{convert::TryFrom, path::PathBuf};

#[derive(PartialEq, Eq, Debug)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub password: String,
}

pub struct NewUser {
    pub name: String,
    pub password: String,
}

impl TryFrom<&Row<'_>> for User {
    type Error = Error;

    fn try_from(row: &Row) -> Result<Self, Self::Error> {
        let r = Self {
            id: row.get(0)?,
            name: row.get(1)?,
            password: row.get(2)?,
        };
        Ok(r)
    }
}

impl TryFrom<Row<'_>> for User {
    type Error = Error;

    fn try_from(row: Row) -> Result<Self, Self::Error> {
        Self::try_from(&row)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AccessLevel {
    Public = 1,
    Authenticated = 2,
    Restricted = 3,
}

#[derive(PartialEq, Eq, Debug)]
pub struct Share {
    pub id: i32,
    pub name: String,
    pub path: PathBuf,
    pub access_level: AccessLevel,
    pub upload_allowed: bool,
}

impl PartialEq<&Self> for Share {
    fn eq(&self, other: &&Self) -> bool {
        (
            self.id,
            &self.name,
            &self.path,
            self.access_level,
            self.upload_allowed,
        ) == (
            other.id,
            &other.name,
            &other.path,
            other.access_level,
            other.upload_allowed,
        )
    }
}

pub struct NewShare {
    pub name: String,
    pub path: PathBuf,
    pub access_level: AccessLevel,
    pub upload_allowed: bool,
}

impl FromSql for AccessLevel {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value.as_i64()? {
            1 => Ok(AccessLevel::Public),
            2 => Ok(AccessLevel::Authenticated),
            3 => Ok(AccessLevel::Restricted),
            v => Err(FromSqlError::OutOfRange(v)),
        }
    }
}

impl ToSql for AccessLevel {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>, rusqlite::Error> {
        Ok((*self as i32).into())
    }
}

struct PathBufWrapper(PathBuf);

impl FromSql for PathBufWrapper {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Text(p) | ValueRef::Blob(p) => Ok(Self(PathBuf::from(
                OsString::from_bytes(p).map_err(|e| FromSqlError::Other(e.into()))?,
            ))),
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

impl PathBufWrapper {
    pub fn into_inner(self) -> PathBuf {
        self.0
    }
}

impl TryFrom<&Row<'_>> for Share {
    type Error = Error;

    fn try_from(row: &Row) -> Result<Self, Self::Error> {
        let r = Self {
            id: row.get(0)?,
            name: row.get(1)?,
            path: row.get::<_, PathBufWrapper>(2)?.into_inner(),
            access_level: row.get(3)?,
            upload_allowed: row.get(4)?,
        };
        Ok(r)
    }
}

impl TryFrom<Row<'_>> for Share {
    type Error = Error;

    fn try_from(row: Row) -> Result<Self, Self::Error> {
        Self::try_from(&row)
    }
}
