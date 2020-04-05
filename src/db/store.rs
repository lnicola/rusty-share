use super::models::{AccessLevel, User};
use crate::Error;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, NO_PARAMS};
use std::path::PathBuf;

type DbResult<T> = Result<T, Error>;

#[derive(Clone)]
pub struct SqliteStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteStore {
    pub fn new(url: &str) -> DbResult<Self> {
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
             )
             order by id",
        )?;
        let shares = stmt
            .query_map(params![user_id, user_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(shares)
    }

    pub fn create_share(&self, name: &str, path: &str, access_level: AccessLevel) -> DbResult<i32> {
        let conn = self.pool.get()?;
        conn.execute(
            "insert into shares(name, path, access_level) values(?, ?, ?)",
            params![name, path, access_level as i32],
        )?;
        let id = conn.last_insert_rowid() as i32;
        Ok(id)
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
    use crate::db::models::AccessLevel;

    fn get_store() -> DbResult<SqliteStore> {
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
        store.insert_user("test_user", "breakme")?;
        assert!(store.users_exist()?);
        Ok(())
    }

    #[test]
    fn find_user() -> DbResult<()> {
        let store = get_store()?;
        assert!(store.find_user("test_user")?.is_none());
        store.insert_user("test_user", "breakme")?;
        let user = store.find_user("test_user")?.unwrap();
        assert_eq!(user.name, "test_user");
        assert_eq!(user.password, "breakme");
        Ok(())
    }

    #[test]
    fn update_password_by_id() -> DbResult<()> {
        let store = get_store()?;
        let id = store.insert_user("test_user", "breakme")?;
        store.update_password_by_id(id, "betterpass")?;
        let user = store.find_user("test_user")?.unwrap();
        assert_eq!(user.name, "test_user");
        assert_eq!(user.password, "betterpass");
        Ok(())
    }

    #[test]
    fn update_password_by_name() -> DbResult<()> {
        let store = get_store()?;
        store.insert_user("test_user", "breakme")?;
        store.update_password_by_name("test_user", "betterpass")?;
        let user = store.find_user("test_user")?.unwrap();
        assert_eq!(user.name, "test_user");
        assert_eq!(user.password, "betterpass");
        Ok(())
    }

    #[test]
    fn lookup_session() -> DbResult<()> {
        let store = get_store()?;
        let user_id = store.insert_user("test_user", "breakme")?;
        assert!(store.lookup_session(b"1234")?.is_none());
        store.create_session(b"1234", user_id)?;
        assert_eq!(
            store.lookup_session(b"1234")?,
            Some((user_id, String::from("test_user")))
        );
        Ok(())
    }

    #[test]
    fn lookup_share_public() -> DbResult<()> {
        let store = get_store()?;
        assert!(store.lookup_share("public_share", None)?.is_none());
        store.create_share("public_share", "public", AccessLevel::Public)?;
        assert_eq!(
            store.lookup_share("public_share", None)?,
            Some(PathBuf::from("public"))
        );
        Ok(())
    }

    #[test]
    fn lookup_share_authenticated() -> DbResult<()> {
        let store = get_store()?;
        let user_id = store.insert_user("test_user", "breakme")?;
        store.create_share(
            "authenticated_share",
            "authenticated",
            AccessLevel::Authenticated,
        )?;
        assert!(store.lookup_share("authenticated_share", None)?.is_none());
        assert_eq!(
            store.lookup_share("authenticated_share", Some(user_id))?,
            Some(PathBuf::from("authenticated"))
        );
        Ok(())
    }

    #[test]
    fn lookup_share_restricted() -> DbResult<()> {
        let store = get_store()?;
        let user_id = store.insert_user("test_user", "breakme")?;
        let another_user_id = store.insert_user("test_user2", "metoo")?;
        let share_id =
            store.create_share("restricted_share", "restricted", AccessLevel::Restricted)?;
        assert!(store.lookup_share("restricted_share", None)?.is_none());
        assert!(store
            .lookup_share("restricted_share", Some(user_id))?
            .is_none());
        store.grant_user_share(user_id, share_id)?;
        assert_eq!(
            store.lookup_share("restricted_share", Some(user_id))?,
            Some(PathBuf::from("restricted"))
        );
        assert!(store
            .lookup_share("restricted_share", Some(another_user_id))?
            .is_none());
        store.revoke_user_share(user_id, share_id)?;
        assert!(store
            .lookup_share("restricted_share", Some(user_id))?
            .is_none());
        Ok(())
    }

    #[test]
    fn get_share_names() -> DbResult<()> {
        let store = get_store()?;
        let user_id = store.insert_user("test_user", "breakme")?;
        let another_user_id = store.insert_user("test_user2", "metoo")?;

        store.create_share("public_share", "public", AccessLevel::Public)?;
        store.create_share(
            "authenticated_share",
            "authenticated",
            AccessLevel::Authenticated,
        )?;
        let share_id =
            store.create_share("restricted_share", "restricted", AccessLevel::Restricted)?;

        assert_eq!(store.get_share_names(None)?, ["public_share"]);
        let get_shares = |user_id| -> DbResult<Vec<String>> {
            let mut shares = store.get_share_names(user_id)?;
            shares.sort();
            Ok(shares)
        };
        assert_eq!(
            get_shares(Some(user_id))?,
            ["authenticated_share", "public_share"]
        );
        store.grant_user_share(user_id, share_id)?;
        assert_eq!(
            get_shares(Some(user_id))?,
            ["authenticated_share", "public_share", "restricted_share"]
        );
        assert_eq!(
            get_shares(Some(another_user_id))?,
            ["authenticated_share", "public_share"]
        );
        store.revoke_user_share(user_id, share_id)?;
        assert_eq!(
            get_shares(Some(user_id))?,
            ["authenticated_share", "public_share"]
        );
        Ok(())
    }
}
