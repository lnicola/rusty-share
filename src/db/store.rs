use super::models::User;
use crate::Error;
#[cfg(FALSE)]
use diesel::r2d2::{self, ConnectionManager};
use rusqlite::{params, Connection, OptionalExtension, NO_PARAMS};
use std::path::PathBuf;

#[cfg(FALSE)]
type Pool = r2d2::Pool<ConnectionManager<Connection>>;
type DbResult<T> = Result<T, Error>;

#[derive(Clone)]
pub struct SqliteStore {
    #[cfg(FALSE)]
    pool: Pool,
    url: String,
}

impl SqliteStore {
    pub fn new(url: &str) -> Self {
        Self {
            #[cfg(FALSE)]
            pool: Pool::new(ConnectionManager::new(url.clone())).unwrap(),
            url: url.to_string(),
        }
    }

    fn get_rusqlite_conn(&self) -> DbResult<Connection> {
        let conn = Connection::open(&self.url)?;
        Ok(conn)
    }

    pub fn initialize_database(&self) -> DbResult<()> {
        let conn = self.get_rusqlite_conn()?;
        conn.execute(include_str!("../../db/users.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/users.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/sessions.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/shares.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/user_shares.sql"), NO_PARAMS)?;
        Ok(())
    }

    pub fn insert_user(&self, name: &str, password: &str) -> DbResult<i32> {
        let conn = self.get_rusqlite_conn()?;
        conn.execute(
            "insert into users(name, password) values(?, ?)",
            params![name, password],
        )?;
        let id = conn.last_insert_rowid() as i32;
        Ok(id)
    }

    pub fn users_exist(&self) -> DbResult<bool> {
        let conn = self.get_rusqlite_conn()?;
        let r = conn.query_row("select exists(select * from users)", NO_PARAMS, |r| {
            r.get::<_, i32>(0)
        })? == 1;
        Ok(r)
    }

    pub fn update_password_by_id(&self, user_id: i32, password: &str) -> DbResult<usize> {
        let conn = self.get_rusqlite_conn()?;
        let count = conn.execute(
            "update users set password = ? where id = ?",
            params![password, user_id],
        )?;
        Ok(count)
    }

    pub fn update_password_by_name(&self, name: &str, password: &str) -> DbResult<usize> {
        let conn = self.get_rusqlite_conn()?;
        let count = conn.execute(
            "update users set password = ? where name = ?",
            params![password, name],
        )?;
        Ok(count)
    }

    pub fn find_user(&self, name: &str) -> DbResult<Option<User>> {
        let conn = self.get_rusqlite_conn()?;
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
        let conn = self.get_rusqlite_conn()?;
        conn.execute(
            "insert into sessions(id, user_id) values(?, ?)",
            params![id, user_id],
        )?;
        Ok(())
    }

    pub fn lookup_session(&self, id: &[u8]) -> DbResult<Option<(i32, String)>> {
        let conn = self.get_rusqlite_conn()?;
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
        let conn = self.get_rusqlite_conn()?;
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
        let conn = self.get_rusqlite_conn()?;
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
        let conn = self.get_rusqlite_conn()?;
        conn.execute(
            "insert into shares(name, path, access_level) values(?, ?, 2)",
            params![name, path],
        )?;
        let id = conn.last_insert_rowid();
        Ok(id)
    }
}
