use bytes::BytesMut;
use http::header::{HeaderValue, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use http::{Response, StatusCode};
use hyper::Body;
use std::fmt::Write;

pub fn page(html: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}

pub fn archive(content_length: u64, body: Body, file_name: &str) -> Response<Body> {
    let content_disposition =
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{}", file_name)).unwrap();
    Response::builder()
        .header(CONTENT_DISPOSITION, content_disposition)
        .header(CONTENT_LENGTH, content_length_value(content_length))
        .header(CONTENT_TYPE, "application/x-tar")
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

fn content_length_value(content_length: u64) -> HeaderValue {
    const MAX_DECIMAL_U64_BYTES: usize = 20;

    let mut len_buf = BytesMut::with_capacity(MAX_DECIMAL_U64_BYTES);
    write!(len_buf, "{}", content_length).expect("BytesMut can hold a decimal u64");

    // safe because u64 Display is ascii numerals
    unsafe { HeaderValue::from_shared_unchecked(len_buf.freeze()) }
}
