//! HTTP/2 on the browser side of the proxy: converting h2 streams to the
//! recorded text form (`METHOD path HTTP/2`, like `http/h2.rs` records) and
//! responses in either text form back to h2.

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::http::client::final_response;
use crate::http::request::{find, split_head_body, RawRequest};
use crate::http::response::{dechunk, parse_response_head};
use crate::http::target::Target;

/// Largest request body read from a browser stream.
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// Response headers HTTP/2 forbids (RFC 9113 8.2.2).
const DROPPED: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

/// The text form of a browser h2 request: `METHOD path HTTP/2`, `host`, the
/// other headers (cookie crumbs joined into one header, RFC 9113 8.2.3), body.
pub fn request_text(parts: &http::request::Parts, body: &[u8], target: &Target) -> Vec<u8> {
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let header = |n: &str| parts.headers.get(n).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    let authority =
        parts.uri.authority().map(|a| a.to_string()).or_else(|| header("host")).unwrap_or_else(|| target.host_header());
    let mut out = format!("{} {path} HTTP/2\r\nhost: {authority}\r\n", parts.method);
    let mut cookies = Vec::new();
    for (k, v) in &parts.headers {
        let v = String::from_utf8_lossy(v.as_bytes());
        match k.as_str() {
            "host" => {}
            "cookie" => cookies.push(v),
            name => out.push_str(&format!("{name}: {v}\r\n")),
        }
    }
    if !cookies.is_empty() {
        out.push_str(&format!("cookie: {}\r\n", cookies.join("; ")));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Rewrites an `HTTP/2` text request as HTTP/1.1 for an origin without h2:
/// the version changes and a body gets a Content-Length. Other requests are
/// returned unchanged.
pub fn to_http1(request: &[u8]) -> Vec<u8> {
    let req = RawRequest::from_bytes(request.to_vec());
    let Ok(head) = req.head() else { return request.to_vec() };
    if !head.version.eq_ignore_ascii_case("HTTP/2") {
        return request.to_vec();
    }
    let line_end = find(request, b"\r\n").unwrap_or(request.len());
    let mut out = format!("{} {} HTTP/1.1", head.method, head.target).into_bytes();
    out.extend_from_slice(&request[line_end..]);
    let req = RawRequest::from_bytes(out);
    let needs_length = matches!(head.method.to_ascii_uppercase().as_str(), "POST" | "PUT" | "PATCH")
        && !head.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    let req = if needs_length && req.body().is_empty() { req.set_header("Content-Length", "0") } else { req };
    req.update_content_length().into_bytes()
}

/// Converts a response in text form (HTTP/1.x from the origin, `HTTP/2` from
/// the h2 client, or a brainproxy error) to an h2 response and its body.
/// Connection-specific headers are dropped and chunked bodies de-chunked.
pub fn response_parts(response: &[u8], method: &str) -> Result<(http::Response<()>, Bytes)> {
    let resp = final_response(response);
    let head = parse_response_head(resp)?;
    if head.status < 200 {
        return Err(Error::Protocol(format!("can't relay a {} response over HTTP/2", head.status)));
    }
    let raw_body = split_head_body(resp).1;
    let chunked = head.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked { dechunk(raw_body) } else { raw_body.to_vec() };
    let mut out = http::Response::builder().status(head.status);
    for (k, v) in &head.headers {
        let name = k.trim().to_ascii_lowercase();
        // A Content-Length that no longer matches the body would break the stream.
        let stale_length = name == "content-length"
            && (chunked || (v.trim() != body.len().to_string() && !method.eq_ignore_ascii_case("HEAD")));
        if DROPPED.contains(&name.as_str()) || stale_length {
            continue;
        }
        let (Ok(n), Ok(v)) = (http::HeaderName::from_bytes(name.as_bytes()), http::HeaderValue::from_str(v.trim()))
        else {
            continue;
        };
        out = out.header(n, v);
    }
    let resp = out.body(()).map_err(|e| Error::Protocol(format!("bad response for HTTP/2: {e}")))?;
    Ok((resp, Bytes::from(body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_browser_requests() {
        let req = http::Request::builder()
            .method("POST")
            .uri("https://a.test:8443/x?y=1")
            .header("cookie", "a=1")
            .header("x-a", "1")
            .header("cookie", "b=2")
            .body(())
            .unwrap();
        let t = Target { scheme: "https".into(), host: "a.test".into(), port: 8443 };
        let text = request_text(&req.into_parts().0, b"hi", &t);
        assert_eq!(text, b"POST /x?y=1 HTTP/2\r\nhost: a.test:8443\r\nx-a: 1\r\ncookie: a=1; b=2\r\n\r\nhi");
        assert_eq!(
            to_http1(&text),
            b"POST /x?y=1 HTTP/1.1\r\nhost: a.test:8443\r\nx-a: 1\r\ncookie: a=1; b=2\r\nContent-Length: 2\r\n\r\nhi"
        );
        assert_eq!(
            to_http1(b"POST / HTTP/2\r\nhost: a\r\n\r\n"),
            b"POST / HTTP/1.1\r\nhost: a\r\nContent-Length: 0\r\n\r\n"
        );
        let h1 = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(to_http1(h1), h1);
    }

    #[test]
    fn converts_responses() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nConnection: keep-alive\r\nX-A: 1\r\n\
                    Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let (resp, body) = response_parts(raw, "GET").unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().len(), 1);
        assert_eq!(&body[..], b"abc");
        // A stale Content-Length is dropped; HEAD keeps it.
        let raw = b"HTTP/2 200\r\ncontent-length: 10\r\n\r\nabc";
        assert!(response_parts(raw, "GET").unwrap().0.headers().get("content-length").is_none());
        assert!(response_parts(raw, "HEAD").unwrap().0.headers().get("content-length").is_some());
        assert!(response_parts(b"HTTP/1.1 101 Switching Protocols\r\n\r\n", "GET").is_err());
    }
}
