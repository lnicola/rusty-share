use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginForm {
    pub user: String,
    pub pass: String,
}

#[derive(Deserialize)]
pub struct Redirect {
    pub redirect: String,
}

#[derive(Deserialize)]
#[serde(transparent)]
pub struct Files {
    pub s: Vec<(String, String)>,
}
