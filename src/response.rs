use cookie::Cookie;
use http::header::{
    HeaderValue, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, SET_COOKIE,
};
use http::{Response, StatusCode};
use hyper::Body;

pub fn page(html: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}

pub fn static_page(html: &'static str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}

pub fn login_ok(session_id: String) -> Response<Body> {
    let cookie = Cookie::new("sid", session_id);
    Response::builder()
        .status(StatusCode::FOUND)
        .header(
            SET_COOKIE,
            HeaderValue::from_str(&cookie.to_string()).unwrap(),
        )
        .header(LOCATION, HeaderValue::from_static("/"))
        .body(Body::empty())
        .unwrap()
}

pub fn login_redirect() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(
            SET_COOKIE,
            HeaderValue::from_str(&Cookie::named("sid").to_string()).unwrap(),
        )
        .header(LOCATION, HeaderValue::from_static("/login"))
        .body(Body::empty())
        .unwrap()
}

pub fn archive(content_length: u64, body: Body, file_name: &str) -> Response<Body> {
    let content_disposition =
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{}", file_name)).unwrap();
    Response::builder()
        .header(CONTENT_DISPOSITION, content_disposition)
        .header(CONTENT_TYPE, "application/x-tar")
        .header(CONTENT_LENGTH, HeaderValue::from(content_length))
        .body(body)
        .unwrap()
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

pub fn method_not_allowed() -> Response<Body> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(Body::empty())
        .unwrap()
}

pub fn internal_server_error() -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::empty())
        .unwrap()
}
