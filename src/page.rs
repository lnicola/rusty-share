use crate::db::models::Share;
use crate::error::Error;
use crate::response;
use crate::share_entry::ShareEntry;
use axum::response::Response;
use horrorshow::helper::doctype;
use horrorshow::{html, Raw, Template};
use http::header::SET_COOKIE;
use http::HeaderValue;
use std::path::Path;

pub fn index(
    share_name: &str,
    path: &Path,
    entries: &[ShareEntry],
    upload_allowed: bool,
    user_name: Option<String>,
) -> Result<Response, Error> {
    let page = html! {
        : doctype::HTML;
        html {
            head {
                meta(name="viewport", content="width=device-width, initial-scale=1");
                title {
                    : Raw("Index of ");
                    : share_name;
                    : Raw("/");
                    : path.to_string_lossy().as_ref();
                }
                style { : Raw(include_str!("../assets/style.css")); }
                @ if upload_allowed {
                    script { : Raw(include_str!("../assets/index.js")); }
                }
            }
            body {
                form(method="POST") {
                    div(class="view") {
                        p {
                            @ if let Some(user) = user_name {
                                : Raw("Logged in as ");
                                : user;
                                : Raw(" ");
                            } else {
                                : Raw("Browsing anonymously ");
                            }
                            a(href="/login") { : Raw("login") }
                        }
                        div(class="entry header") {
                            div { }
                            div { : Raw("Name") }
                            div { : Raw("Size") }
                            div { : Raw("Last modified") }
                        }
                        div(class="entry") {
                            div { }
                            div { a(href=Raw("..")) { : Raw("..") } }
                            div { }
                            div { }
                        }
                        @ for entry in entries {
                            div(class="entry") {
                                input(name="s", value=entry.link(), type="checkbox");
                                a(href=entry.link()) { : entry.display_name() }
                                div { : Raw(entry.size()) }
                                div { : Raw(entry.date_string()) }
                            }
                        }
                    }
                    input(type="submit", value="Download");
                }
                @ if upload_allowed {
                    form(method="POST") {
                        input(type="file", id="file", multiple);
                        input(type="button", id="upload", value="Upload");
                    }
                }
            }
        }
    };
    let page = page.into_string()?;
    Ok(response::page(page))
}

pub fn shares(shares: Vec<Share>, user_name: Option<String>) -> Result<Response, Error> {
    let page = html! {
        : doctype::HTML;
        html {
            head {
                meta(name="viewport", content="width=device-width, initial-scale=1");
                title {
                    : Raw("Browse shares");
                }
                style { : Raw(include_str!("../assets/style.css")); }
            }
            body {
                div(class="view") {
                    p {
                        @ if let Some(user) = user_name {
                            : Raw("Logged in as ");
                            : user;
                            : Raw(" ");
                        } else {
                            : Raw("Browsing anonymously ");
                        }
                        a(href="/login") { : Raw("login") }
                    }
                    div(class="entry header share") {
                        div { : Raw("Name") }
                    }
                    @ for share in shares {
                        div(class="entry share") {
                            a(href=Raw(percent_encoding::utf8_percent_encode(&share.name, percent_encoding::NON_ALPHANUMERIC).to_string())) { : share.name }
                        }
                    }
                }
            }
        }
    };
    let page = page.into_string()?;
    Ok(response::page(page))
}

pub fn login(message: Option<&str>) -> Result<Response, Error> {
    let page = html! {
        : doctype::HTML;
        html {
            head {
                meta(name="viewport", content="width=device-width, initial-scale=1");
                title {
                    : Raw("Login");
                }
                style { : Raw(include_str!("../assets/style.css")); }
            }
            body {
                div(class="login-page") {
                    form(method="POST", class="form") {
                        input(type="text", name="user", placeholder="username", autofocus);
                        input(type="password", name="pass", placeholder="password");
                        button { : Raw("Log in") }
                        @ if let Some(message) = message {
                            p(class="message") { : message }
                        }
                    }
                }

           }
        }
    };
    let page = page.into_string()?;
    let mut response = response::page(page);
    if message.is_some() {
        let cookie = "sid=; HttpOnly; SameSite=Lax; Max-Age=0";
        response.headers_mut().insert(
            SET_COOKIE,
            // HeaderValue::from_str(&Cookie::named("sid").to_string()).unwrap(),
            HeaderValue::from_static(cookie),
        );
    }
    Ok(response)
}
