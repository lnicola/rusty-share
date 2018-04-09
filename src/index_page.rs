#[cfg(target_os = "windows")]
use OsStrExt3;
use ShareEntry;
use bytesize::ByteSize;
use chrono_humanize::HumanTime;
use failure::{Error, ResultExt};
use horrorshow::helper::doctype;
use horrorshow::prelude::*;
#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;
use url::percent_encoding;

pub fn render(entries: Vec<ShareEntry>) -> Result<String, Error> {
    let page = html! {
        : doctype::HTML;
        html {
            head {
                script { : Raw(include_str!("../assets/player.js")) }
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
                            th;
                            th { : Raw("Name") }
                            th { : Raw("Size") }
                            th { : Raw("Last modified") }
                        }
                        tr { td; td { a(href=Raw("..")) { : Raw("..") } } td; td; }
                        @ for ShareEntry { mut name, is_dir, size, date } in entries {
                            |tmpl| {
                                let mut display_name = name;
                                if is_dir {
                                    display_name.push("/");
                                }
                                let link = percent_encoding::percent_encode(
                                    display_name.as_bytes(),
                                    percent_encoding::DEFAULT_ENCODE_SET,
                                ).to_string();
                                let name = display_name.to_string_lossy().into_owned();
                                tmpl << html! {
                                    tr {
                                        td { input(name="s", value=Raw(&link), type="checkbox") }
                                        td { a(href=Raw(&link)) { : name } }
                                        td {
                                            @ if !is_dir {
                                                : Raw(ByteSize::b(size).to_string(false))
                                            }
                                        }
                                        td { : Raw(HumanTime::from(date).to_string()) }
                                    }
                                }
                            }
                        }
                    }
                    input(type="submit", value="Download");
                }
            }
        }
    };
    Ok(page.into_string()
        .with_context(|_| "Unable to render index page")?)
}
