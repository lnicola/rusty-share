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
                meta(name="viewport", content="width=device-width, initial-scale=1");
                style { : Raw(include_str!("../assets/style.css")); }
            }
            body {
                form(method="POST") {
                    div(class="view") {
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
                                div { input(name="s", value=entry.link(), type="checkbox") }
                                div { a(href=entry.link()) { : entry.name() } }
                                div { : Raw(entry.size()) }
                                div { : Raw(entry.date_string()) }
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
                meta(name="viewport", content="width=device-width, initial-scale=1");
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
