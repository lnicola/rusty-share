use failure::{Error, ResultExt};
use horrorshow::helper::doctype;
use horrorshow::prelude::*;
use horrorshow::{append_html, html};
use ShareEntry;

pub fn render(entries: &[ShareEntry]) -> Result<String, Error> {
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
                            |tmpl| {
                                tmpl << html! {
                                    tr {
                                        td { input(name="s", value=Raw(&entry.link()), type="checkbox") }
                                        td { a(href=Raw(entry.link())) { : entry.name() } }
                                        td { : Raw(entry.size()) }
                                        td { : Raw(entry.date_string()) }
                                    }
                                }
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
    Ok(page
        .into_string()
        .with_context(|_| "Unable to render index page")?)
}
