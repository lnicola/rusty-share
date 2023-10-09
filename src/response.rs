use axum::body::{self, Body};
use axum::response::Response;
use http::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, SET_COOKIE};
use http::{HeaderValue, StatusCode, Uri};

pub fn page(html: String) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(body::boxed(Body::from(html)))
        .unwrap()
}

pub fn login_ok(session_id: String, redirect: &str) -> Response {
    let cookie = format!("sid={}; HttpOnly; SameSite=Lax; Max-Age=86400", session_id);
    // let cookie = Cookie::build("sid", session_id)
    //     .max_age(Duration::days(1))
    //     .http_only(true)
    //     // .secure(true)
    //     .same_site(SameSite::Lax)
    //     .finish();
    Response::builder()
        .status(StatusCode::FOUND)
        .header(SET_COOKIE, HeaderValue::from_str(&cookie).unwrap())
        .header(LOCATION, HeaderValue::from_str(redirect).unwrap())
        .body(body::boxed(Body::empty()))
        .unwrap()
}

pub fn encode_redirect_uri(path: &Uri) -> String {
    let path = path.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let path =
        percent_encoding::utf8_percent_encode(path, percent_encoding::NON_ALPHANUMERIC).to_string();
    format!("/login?redirect={}", path)
}

pub fn login_redirect(path: &Uri, destroy_session: bool) -> Response {
    let path = encode_redirect_uri(path);
    let mut builder = Response::builder();

    if destroy_session {
        let cookie = "sid=; HttpOnly; SameSite=Lax; Max-Age=0";
        // let cookie = Cookie::build("sid", "").max_age(Duration::zero()).finish();
        builder = builder.header(SET_COOKIE, HeaderValue::from_static(cookie));
    }
    builder
        .status(StatusCode::FOUND)
        .header(LOCATION, HeaderValue::from_str(&path).unwrap())
        .body(body::boxed(Body::empty()))
        .unwrap()
}

pub fn archive(content_length: u64, body: Body, file_name: &str) -> Response {
    let file_name =
        percent_encoding::utf8_percent_encode(file_name, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let content_disposition =
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{}", file_name)).unwrap();
    Response::builder()
        .header(CONTENT_DISPOSITION, content_disposition)
        .header(CONTENT_TYPE, "application/x-tar")
        .header(CONTENT_LENGTH, HeaderValue::from(content_length))
        .body(body::boxed(body))
        .unwrap()
}

pub fn no_content() -> Response {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(body::boxed(Body::empty()))
        .unwrap()
}

pub fn found(location: &str) -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(LOCATION, HeaderValue::from_str(location).unwrap())
        .body(body::boxed(Body::empty()))
        .unwrap()
}

pub fn forbidden() -> Response {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(body::boxed(Body::empty()))
        .unwrap()
}

pub fn not_found() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(body::boxed(Body::empty()))
        .unwrap()
}

pub fn internal_server_error() -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(body::boxed(Body::empty()))
        .unwrap()
}
