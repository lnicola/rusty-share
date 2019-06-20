#[derive(Debug, Queryable)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub password: String,
}

pub enum AccessLevel {
    Public = 1,
    Authenticated = 2,
    Restricted = 3,
}
