use cookie::Cookie;
use horrorshow::helper::doctype;
use horrorshow::prelude::*;
use horrorshow::{append_html, html};
use http::header::HeaderValue;
use http::header::SET_COOKIE;
use http::Response;
use hyper::Body;
use log::{error, log};
use response;
use share_entry::ShareEntry;

pub fn index(entries: &[ShareEntry]) -> Response<Body> {
    let page = html! {
        : doctype::HTML;
        html {
            head {
                style { : Raw(include_str!("../assets/style.css")); }
            }
            body {
                form(method="POST") {
                    table(class="view") {
                        colgroup {
                            col(class="selected");
                            col(class="name");
                            col(class="size");
                            col(class="date");
                        }
                        tr(class="header") {
                            th { }
                            th { : Raw("Name") }
                            th { : Raw("Size") }
                            th { : Raw("Last modified") }
                        }
                        tr { td { } td { a(href=Raw("..")) { : Raw("..") } } td { } td { } }
                        @ for entry in entries {
                            tr {
                                td { input(name="s", value=entry.link(), type="checkbox") }
                                td { a(href=entry.link()) { : entry.name() } }
                                td { : Raw(entry.size()) }
                                td { : Raw(entry.date_string()) }
                            }
                        }
                    }
                    input(type="submit", value="Download");
                }
                div(id="player-section", class="hidden") {
                    p(id="song-title") { }
                    div {
                        audio(id="player", preload="auto", controls) { }
                    }
                    div {
                        button(id="shuffle", class="media-control", type="button") { : Raw("🔀") }
                        button(id="prev", class="media-control", type="button") { : Raw("⏮") }
                        button(id="next", class="media-control", type="button") { : Raw("⏭") }
                    }
                }
                script { : Raw(include_str!("../assets/player.js")) }
            }
        }
    };
    match page.into_string() {
        Ok(page) => response::page(page),
        Err(e) => {
            error!("{}", e);
            response::internal_server_error()
        }
    }
}

pub fn login(message: Option<&str>) -> Response<Body> {
    let page = html! {
        : doctype::HTML;
        html {
            head {
                style { : Raw(include_str!("../assets/style.css")); }
            }
            body {
                @ if let Some(message) = message {
                    div(class="login-notification") { : message }
                }
                form(method="POST") {
                    div {
                        label(for="user") { : Raw("User name") }
                        input(type="text", id="user", name="user");
                    }
                    div {
                        label(for="pass") { : Raw("Password") }
                        input(type="password", id="pass", name="pass");
                    }
                    input(type="submit", value="Log in");
                }
           }
        }
    };
    match page.into_string() {
        Ok(page) => {
            let mut response = response::page(page);
            if message.is_some() {
                response.headers_mut().insert(
                    SET_COOKIE,
                    HeaderValue::from_str(&Cookie::named("sid").to_string()).unwrap(),
                );
            }
            response
        }
        Err(e) => {
            error!("{}", e);
            response::internal_server_error()
        }
    }
}
