use super::models::{NewShare, NewUser, Share, User};
use crate::Error;

use os_str_bytes::OsStrBytes;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, NO_PARAMS};

use std::convert::TryFrom;
use std::path::Path;

type DbResult<T> = Result<T, Error>;

#[derive(Clone)]
pub struct SqliteStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteStore {
    pub fn new(url: &Path) -> DbResult<Self> {
        let store = Self {
            pool: Pool::new(SqliteConnectionManager::file(url))?,
        };
        Ok(store)
    }

    pub fn initialize_database(&self) -> DbResult<()> {
        let conn = self.pool.get()?;
        conn.execute(include_str!("../../db/users.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/sessions.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/shares.sql"), NO_PARAMS)?;
        conn.execute(include_str!("../../db/user_shares.sql"), NO_PARAMS)?;
        Ok(())
    }

    pub fn create_user(&self, user: NewUser) -> DbResult<User> {
        let conn = self.pool.get()?;
        conn.execute(
            "insert into users(name, password) values(?, ?)",
            params![user.name, user.password],
        )?;
        let user = User {
            id: conn.last_insert_rowid() as i32,
            name: user.name,
            password: user.password,
        };
        Ok(user)
    }

    pub fn users_exist(&self) -> DbResult<bool> {
        let conn = self.pool.get()?;
        let r = conn.query_row("select exists(select * from users)", NO_PARAMS, |r| {
            r.get(0)
        })?;
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
                "select *
                 from users
                 where name = ?",
                params![name],
                |row| User::try_from(row),
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
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(r)
    }

    pub fn lookup_share(&self, name: &str, user_id: Option<i32>) -> DbResult<Option<Share>> {
        let conn = self.pool.get()?;
        let share = conn
            .query_row(
                "select *
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
                |row| Share::try_from(row),
            )
            .optional()?;
        Ok(share)
    }

    pub fn get_accessible_shares(&self, user_id: Option<i32>) -> DbResult<Vec<Share>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "select *
             from shares
             where (access_level = 1
                 or access_level = 2 and ? is not null
                 or access_level = 3 and exists (
                     select *
                     from user_shares
                     where user_id = ? and share_id = shares.id
                  )
             )
             order by id",
        )?;
        let shares = stmt
            .query_map(params![user_id, user_id], |row| Share::try_from(row))?
            .collect::<Result<_, _>>()?;
        Ok(shares)
    }

    pub fn create_share(&self, share: NewShare) -> DbResult<Share> {
        let conn = self.pool.get()?;
        conn.execute(
            "insert into shares(name, path, access_level, upload_allowed) values(?, ?, ?, ?)",
            params![
                share.name,
                share.path.to_bytes().as_ref(),
                share.access_level as i32,
                share.upload_allowed
            ],
        )?;
        let share = Share {
            id: conn.last_insert_rowid() as i32,
            name: share.name,
            path: share.path,
            access_level: share.access_level,
            upload_allowed: share.upload_allowed,
        };
        Ok(share)
    }

    pub fn grant_user_share(&self, user_id: i32, share_id: i32) -> DbResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "insert into user_shares(user_id, share_id) values(?, ?)",
            params![user_id, share_id],
        )?;
        Ok(())
    }

    pub fn revoke_user_share(&self, user_id: i32, share_id: i32) -> DbResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "delete from user_shares where user_id = ? and share_id = ?",
            params![user_id, share_id],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{DbResult, SqliteStore};
    use crate::db::models::{AccessLevel, NewShare, NewUser};

    fn get_store() -> DbResult<SqliteStore> {
        unsafe {
            rusqlite::bypass_sqlite_version_check();
        }

        let store = SqliteStore::new(":memory:")?;
        store.initialize_database()?;
        Ok(store)
    }

    #[test]
    fn initialize() -> DbResult<()> {
        get_store()?;
        Ok(())
    }

    #[test]
    fn users_exists() -> DbResult<()> {
        let store = get_store()?;
        assert!(!store.users_exist()?);
        store.create_user(NewUser {
            name: String::from("test_user"),
            password: String::from("breakme"),
        })?;
        assert!(store.users_exist()?);
        Ok(())
    }

    #[test]
    fn find_user() -> DbResult<()> {
        let store = get_store()?;
        let user = NewUser {
            name: String::from("test_user"),
            password: String::from("breakme"),
        };
        assert!(store.find_user(&user.name)?.is_none());
        let user = store.create_user(user)?;
        assert_eq!(store.find_user(&user.name)?, Some(user));
        Ok(())
    }

    #[test]
    fn update_password_by_id() -> DbResult<()> {
        let store = get_store()?;
        let mut user = store.create_user(NewUser {
            name: String::from("test_user"),
            password: String::from("breakme"),
        })?;
        user.password = String::from("betterpass");
        store.update_password_by_id(user.id, &user.password)?;
        assert_eq!(store.find_user(&user.name)?, Some(user));
        Ok(())
    }

    #[test]
    fn update_password_by_name() -> DbResult<()> {
        let store = get_store()?;
        let mut user = store.create_user(NewUser {
            name: String::from("test_user"),
            password: String::from("breakme"),
        })?;
        user.password = String::from("betterpass");
        store.update_password_by_name(&user.name, &user.password)?;
        assert_eq!(store.find_user(&user.name)?, Some(user));
        Ok(())
    }

    #[test]
    fn lookup_session() -> DbResult<()> {
        let store = get_store()?;
        let user = store.create_user(NewUser {
            name: String::from("test_user"),
            password: String::from("breakme"),
        })?;
        assert!(store.lookup_session(b"1234")?.is_none());
        store.create_session(b"1234", user.id)?;
        assert_eq!(store.lookup_session(b"1234")?, Some((user.id, user.name)));
        Ok(())
    }

    #[test]
    fn lookup_share_public() -> DbResult<()> {
        let store = get_store()?;
        let name = String::from("public_share");
        assert!(store.lookup_share(&name, None)?.is_none());
        let share = NewShare {
            name,
            path: PathBuf::from("public"),
            access_level: AccessLevel::Public,
            upload_allowed: false,
        };
        let share = store.create_share(share)?;
        assert_eq!(store.lookup_share(&share.name, None)?, Some(share));
        Ok(())
    }

    #[test]
    fn lookup_share_authenticated() -> DbResult<()> {
        let store = get_store()?;
        let user = store.create_user(NewUser {
            name: String::from("test_user"),
            password: String::from("breakme"),
        })?;
        let share = store.create_share(NewShare {
            name: String::from("authenticated_share"),
            path: PathBuf::from("authenticated"),
            access_level: AccessLevel::Authenticated,
            upload_allowed: false,
        })?;
        assert!(store.lookup_share(&share.name, None)?.is_none());
        assert_eq!(store.lookup_share(&share.name, Some(user.id))?, Some(share));
        Ok(())
    }

    #[test]
    fn lookup_share_restricted() -> DbResult<()> {
        let store = get_store()?;
        let user = store.create_user(NewUser {
            name: String::from("test_user"),
            password: String::from("breakme"),
        })?;
        let another_user = store.create_user(NewUser {
            name: String::from("test_user2"),
            password: String::from("metoo"),
        })?;

        let share = store.create_share(NewShare {
            name: String::from("restricted_share"),
            path: PathBuf::from("restricted"),
            access_level: AccessLevel::Restricted,
            upload_allowed: false,
        })?;
        assert!(store.lookup_share(&share.name, None)?.is_none());
        assert!(store.lookup_share(&share.name, Some(user.id))?.is_none());
        store.grant_user_share(user.id, share.id)?;
        let id = share.id;
        assert_eq!(
            store.lookup_share(&share.name, Some(user.id))?.as_ref(),
            Some(&share)
        );
        assert!(store
            .lookup_share(&share.name, Some(another_user.id))?
            .is_none());
        store.revoke_user_share(user.id, id)?;
        assert!(store.lookup_share(&share.name, Some(user.id))?.is_none());
        Ok(())
    }

    #[test]
    fn get_share_names() -> DbResult<()> {
        let store = get_store()?;
        let user = store.create_user(NewUser {
            name: String::from("test_user"),
            password: String::from("breakme"),
        })?;
        let another_user = store.create_user(NewUser {
            name: String::from("test_user2"),
            password: String::from("metoo"),
        })?;

        let public_share = store.create_share(NewShare {
            name: String::from("public_share"),
            path: PathBuf::from("public"),
            access_level: AccessLevel::Public,
            upload_allowed: false,
        })?;
        let authenticated_share = store.create_share(NewShare {
            name: String::from("authenticated_share"),
            path: PathBuf::from("authenticated"),
            access_level: AccessLevel::Authenticated,
            upload_allowed: false,
        })?;
        let restricted_share = store.create_share(NewShare {
            name: String::from("restricted_share"),
            path: PathBuf::from("restricted"),
            access_level: AccessLevel::Restricted,
            upload_allowed: false,
        })?;

        assert_eq!(store.get_accessible_shares(None)?, [&public_share]);
        assert_eq!(
            store.get_accessible_shares(Some(user.id))?,
            [&public_share, &authenticated_share]
        );
        store.grant_user_share(user.id, restricted_share.id)?;
        assert_eq!(
            store.get_accessible_shares(Some(user.id))?,
            [&public_share, &authenticated_share, &restricted_share]
        );
        assert_eq!(
            store.get_accessible_shares(Some(another_user.id))?,
            [&public_share, &authenticated_share]
        );
        store.revoke_user_share(user.id, restricted_share.id)?;
        assert_eq!(
            store.get_accessible_shares(Some(user.id))?,
            [&public_share, &authenticated_share]
        );
        Ok(())
    }
}
