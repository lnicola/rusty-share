use super::models::User;
use crate::Error;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, NO_PARAMS};
use std::path::PathBuf;

type DbResult<T> = Result<T, Error>;

#[derive(Clone)]
pub struct SqliteStore {
    pool: Pool<SqliteConnectionManager>,
    url: String,
}

impl SqliteStore {
    pub fn new(url: &str) -> Self {
        Self {
            pool: Pool::new(SqliteConnectionManager::file(url)).unwrap(),
            url: url.to_string(),
        }
    }

    pub fn initialize_database(&self) -> DbResult<()> {
        let conn = self.pool.get()?;
        conn.execute(include_str!("../../db/users.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/users.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/sessions.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/shares.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/user_shares.sql"), NO_PARAMS)?;
        Ok(())
    }

    pub fn insert_user(&self, name: &str, password: &str) -> DbResult<i32> {
        let conn = self.pool.get()?;
        conn.execute(
            "insert into users(name, password) values(?, ?)",
            params![name, password],
        )?;
        let id = conn.last_insert_rowid() as i32;
        Ok(id)
    }

    pub fn users_exist(&self) -> DbResult<bool> {
        let conn = self.pool.get()?;
        let r = conn.query_row("select exists(select * from users)", NO_PARAMS, |r| {
            r.get::<_, i32>(0)
        })? == 1;
        Ok(r)
    }

    pub fn update_password_by_id(&self, user_id: i32, password: &str) -> DbResult<usize> {
        let conn = self.pool.get()?;
        let count = conn.execute(
            "update users set password = ? where id = ?",
            params![password, user_id],
        )?;
        Ok(count)
    }

    pub fn update_password_by_name(&self, name: &str, password: &str) -> DbResult<usize> {
        let conn = self.pool.get()?;
        let count = conn.execute(
            "update users set password = ? where name = ?",
            params![password, name],
        )?;
        Ok(count)
    }

    pub fn find_user(&self, name: &str) -> DbResult<Option<User>> {
        let conn = self.pool.get()?;
        let user = conn
            .query_row(
                "select id, name, password from users where name = ?",
                params![name],
                |r| {
                    Ok(User {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        password: r.get(2)?,
                    })
                },
            )
            .optional()?;
        Ok(user)
    }

    pub fn create_session(&self, id: &[u8], user_id: i32) -> DbResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "insert into sessions(id, user_id) values(?, ?)",
            params![id, user_id],
        )?;
        Ok(())
    }

    pub fn lookup_session(&self, id: &[u8]) -> DbResult<Option<(i32, String)>> {
        let conn = self.pool.get()?;
        let r = conn
            .query_row(
                "select users.id, name
                      from users
                      inner join sessions on sessions.user_id = users.id
                      where sessions.id = ?",
                params![id],
                |row| Ok((row.get::<_, i32>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        Ok(r)
    }

    pub fn lookup_share(&self, name: &str, user_id: Option<i32>) -> DbResult<Option<PathBuf>> {
        let conn = self.pool.get()?;
        let share = conn
            .query_row(
                "select path
                      from shares
                      where name = ?
                        and (access_level = 1
                          or access_level = 2 and ? is not null
                          or access_level = 3 and exists (
                              select *
                              from user_shares
                              where user_id = ? and share_id = shares.id
                          )
                        )",
                params![name, user_id, user_id],
                |row| row.get::<_, String>(0),
            )
            .map(PathBuf::from)
            .optional()?;
        Ok(share)
    }

    pub fn get_share_names(&self, user_id: Option<i32>) -> DbResult<Vec<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "select name
                      from shares
                      where (access_level = 1
                          or access_level = 2 and ? is not null
                          or access_level = 3 and exists (
                              select *
                              from user_shares
                              where user_id = ? and share_id = shares.id
                          )
                        )",
        )?;
        let shares = stmt
            .query_map(params![user_id, user_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(shares)
    }

    pub fn create_share(&self, name: &str, path: &str) -> DbResult<i64> {
        let conn = self.pool.get()?;
        conn.execute(
            "insert into shares(name, path, access_level) values(?, ?, 2)",
            params![name, path],
        )?;
        let id = conn.last_insert_rowid();
        Ok(id)
    }
}
