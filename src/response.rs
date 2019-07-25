use cookie::{Cookie, SameSite};
use http::header::{
    HeaderValue, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, SET_COOKIE,
};
use http::{Response, StatusCode, Uri};
use hyper::Body;
use time::Duration;

pub fn page(html: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}

pub fn login_ok(session_id: String, redirect: &str) -> Response<Body> {
    let cookie = Cookie::build("sid", session_id)
        .max_age(Duration::days(1))
        .http_only(true)
        // .secure(true)
        .same_site(SameSite::Lax)
        .finish();
    Response::builder()
        .status(StatusCode::FOUND)
        .header(
            SET_COOKIE,
            HeaderValue::from_str(&cookie.to_string()).unwrap(),
        )
        .header(LOCATION, HeaderValue::from_str(redirect).unwrap())
        .body(Body::empty())
        .unwrap()
}

pub fn login_redirect(path: &Uri, destroy_session: bool) -> Response<Body> {
    let path = path.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let path =
        percent_encoding::percent_encode(path.as_bytes(), percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let mut builder = Response::builder();

    if destroy_session {
        let cookie = Cookie::build("sid", "").max_age(Duration::zero()).finish();
        builder.header(
            SET_COOKIE,
            HeaderValue::from_str(&cookie.to_string()).unwrap(),
        );
    }
    builder
        .status(StatusCode::FOUND)
        .header(
            LOCATION,
            HeaderValue::from_str(&format!("/login?redirect={}", path)).unwrap(),
        )
        .body(Body::empty())
        .unwrap()
}

pub fn archive(content_length: u64, body: Body, file_name: &str) -> Response<Body> {
    let file_name =
        percent_encoding::percent_encode(file_name.as_bytes(), percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let content_disposition =
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{}", file_name)).unwrap();
    Response::builder()
        .header(CONTENT_DISPOSITION, content_disposition)
        .header(CONTENT_TYPE, "application/x-tar")
        .header(CONTENT_LENGTH, HeaderValue::from(content_length))
        .body(body)
        .unwrap()
}

pub fn archive2(resp: &mut Response<Body>, content_length: u64, file_name: &str) {
    let file_name =
        percent_encoding::percent_encode(file_name.as_bytes(), percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let content_disposition =
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{}", file_name)).unwrap();
    resp.headers_mut()
        .append(CONTENT_DISPOSITION, content_disposition);
    resp.headers_mut()
        .append(CONTENT_TYPE, HeaderValue::from_static("application/x-tar"));
    resp.headers_mut()
        .append(CONTENT_LENGTH, HeaderValue::from(content_length));
}

pub fn found(location: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(LOCATION, HeaderValue::from_str(location).unwrap())
        .body(Body::empty())
        .unwrap()
}

pub fn bad_request() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .unwrap()
}

pub fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .unwrap()
}

pub fn internal_server_error() -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::empty())
        .unwrap()
}
