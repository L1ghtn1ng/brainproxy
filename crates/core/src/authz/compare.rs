//! Response comparison for access-control testing: what changes between two identical
//! requests (noise), how alike two responses are, and which of the owner's values a
//! response gives away.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::capture::decode_body;
use crate::http::client::final_response;
use crate::http::parse_response_head;
use crate::http::request::split_head_body;

/// A response reduced to what the comparison needs.
#[derive(Debug, Clone, Default)]
pub(crate) struct Body {
    pub status: Option<u16>,
    /// Decoded body as text (lossy UTF-8).
    pub text: String,
    /// Leaf values by path (`a.b[0].c`) when the body is a JSON object or array.
    pub json: Option<Vec<(String, String)>>,
}

impl Body {
    pub fn parse(response: &[u8]) -> Body {
        let response = final_response(response);
        let Ok(head) = parse_response_head(response) else { return Body::default() };
        let body = decode_body(&head.headers, split_head_body(response).1);
        let text = String::from_utf8_lossy(&body).into_owned();
        let json = serde_json::from_str::<Value>(text.trim()).ok().filter(|v| v.is_object() || v.is_array()).map(|v| {
            let mut out = Vec::new();
            flatten(&v, String::new(), &mut out);
            out
        });
        Body { status: Some(head.status), text, json }
    }

    pub fn success(&self) -> bool {
        matches!(self.status, Some(200..=299))
    }
}

fn flatten(v: &Value, path: String, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                flatten(v, p, out);
            }
        }
        Value::Array(a) => {
            for (i, v) in a.iter().enumerate() {
                flatten(v, format!("{path}[{i}]"), out);
            }
        }
        Value::String(s) => out.push((path, s.clone())),
        other => out.push((path, other.to_string())),
    }
}

/// Words of a text: runs of letters, digits, `_`, `-` and `@`.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '@'))).filter(|w| !w.is_empty())
}

/// Whether `value` occurs in `text`: as a whole word when it is one, else as a substring.
pub(crate) fn mentions(text: &str, value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if words(value).count() == 1 && words(value).next() == Some(value) {
        words(text).any(|w| w == value)
    } else {
        text.contains(value)
    }
}

/// What differs between two responses to the same request from the same identity:
/// timestamps, nonces, CSRF tokens. Comparisons leave it out.
#[derive(Debug, Default)]
pub(crate) struct Noise {
    paths: HashSet<String>,
    words: HashSet<String>,
}

impl Noise {
    pub fn learn(a: &Body, b: &Body) -> Noise {
        let mut noise = Noise::default();
        if let (Some(ja), Some(jb)) = (&a.json, &b.json) {
            let ma: HashMap<&str, &str> = ja.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let mb: HashMap<&str, &str> = jb.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            for k in ma.keys().chain(mb.keys()) {
                if ma.get(k) != mb.get(k) {
                    noise.paths.insert(k.to_string());
                }
            }
        }
        let wa: HashSet<&str> = words(&a.text).collect();
        let wb: HashSet<&str> = words(&b.text).collect();
        noise.words = wa.symmetric_difference(&wb).map(|w| w.to_string()).collect();
        noise
    }

    fn leaves<'a>(&self, b: &'a Body) -> HashMap<&'a str, &'a str> {
        b.json
            .iter()
            .flatten()
            .filter(|(k, _)| !self.paths.contains(k))
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    fn word_counts<'a>(&self, text: &'a str) -> HashMap<&'a str, usize> {
        let mut m = HashMap::new();
        for w in words(text).filter(|w| !self.words.contains(*w)) {
            *m.entry(w).or_default() += 1;
        }
        m
    }
}

/// How alike two responses are, 0 to 1, leaving out noise. JSON is compared value by
/// value at each path; anything else word by word (Dice coefficient over word counts).
/// A JSON body and a non-JSON one are not alike.
pub(crate) fn similarity(a: &Body, b: &Body, noise: &Noise) -> f64 {
    match (&a.json, &b.json) {
        (Some(_), Some(_)) => {
            let (ma, mb) = (noise.leaves(a), noise.leaves(b));
            let keys: HashSet<&str> = ma.keys().chain(mb.keys()).copied().collect();
            if keys.is_empty() {
                return 1.0;
            }
            let same = keys.iter().filter(|k| ma.get(*k).is_some() && ma.get(*k) == mb.get(*k)).count();
            same as f64 / keys.len() as f64
        }
        (None, None) => {
            let (ca, cb) = (noise.word_counts(&a.text), noise.word_counts(&b.text));
            let (na, nb): (usize, usize) = (ca.values().sum(), cb.values().sum());
            if na + nb == 0 {
                return 1.0;
            }
            let common: usize = ca.iter().map(|(w, n)| (*n).min(cb.get(w).copied().unwrap_or(0))).sum();
            2.0 * common as f64 / (na + nb) as f64
        }
        _ => 0.0,
    }
}

/// The owner's private values: JSON leaves of the baseline that aren't noise, aren't
/// booleans or null, and don't appear in any of `public` (the request itself, the
/// anonymous response), as (path, value).
pub(crate) fn private_values(baseline: &Body, noise: &Noise, public: &[&str]) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    noise
        .leaves(baseline)
        .into_iter()
        .filter(|(_, v)| !v.is_empty() && !matches!(*v, "true" | "false" | "null"))
        .filter(|(_, v)| !public.iter().any(|t| mentions(t, v)))
        .filter(|(k, v)| seen.insert((k.to_string(), v.to_string())))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// How many private values `b` holds: at the same path when it is JSON, anywhere in
/// its text otherwise.
pub(crate) fn private_hits(private: &[(String, String)], b: &Body) -> usize {
    match &b.json {
        Some(leaves) => {
            let m: HashMap<&str, &str> = leaves.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            private.iter().filter(|(k, v)| m.get(k.as_str()) == Some(&v.as_str())).count()
        }
        None => private.iter().filter(|(_, v)| mentions(&b.text, v)).count(),
    }
}

/// A body that says access was refused (when the baseline doesn't say so too).
pub(crate) fn says_denied(text: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(access denied|forbidden|not authori[sz]ed|unauthori[sz]ed|permission denied|not permitted|insufficient (privileges|permissions))\b",
        )
        .expect("valid regex")
    })
    .is_match(text)
}

/// Whether the request names an object: a number, UUID, long hex id, or email address
/// in its path, query or body. Identical responses to such a request are a stronger
/// sign of a bypass than identical responses to `/dashboard`, which may be shared.
pub(crate) fn references_object(target: &str, body: &str) -> bool {
    static UUID: OnceLock<Regex> = OnceLock::new();
    let uuid = UUID.get_or_init(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").expect("valid regex")
    });
    let is_id = |t: &str| {
        (!t.is_empty() && t.len() <= 20 && t.bytes().all(|b| b.is_ascii_digit()))
            || uuid.is_match(t)
            || (t.len() >= 16 && t.bytes().all(|b| b.is_ascii_hexdigit()) && t.bytes().any(|b| b.is_ascii_digit()))
            || (t.contains('@') && t.contains('.'))
    };
    let split = |s: &str| {
        s.split(|c: char| {
            matches!(c, '/' | '?' | '&' | '=' | ',' | ';' | ':' | '"' | '\'' | ' ' | '{' | '}' | '[' | ']')
        })
        .map(|t| crate::scan::message::url_decode(t))
        .collect::<Vec<_>>()
    };
    // Version segments such as /v2/ or /api/1.0/ aren't objects.
    split(target).iter().chain(split(body).iter()).any(|t| is_id(t))
}

/// Paths that suggest a privileged function, where a shared response matters more.
pub(crate) fn privileged_path(path: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(^|[/_.-])(admin|administrator|manage|management|internal|staff|superuser|sudo|console|users|roles|permissions|billing|audit)([/_.-]|$)").expect("valid regex")
    })
    .is_match(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json_resp(status: u16, body: &str) -> Body {
        let raw = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        Body::parse(raw.as_bytes())
    }

    fn html_resp(body: &str) -> Body {
        let raw = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        Body::parse(raw.as_bytes())
    }

    #[test]
    fn noise_leaves_out_changing_fields() {
        let a = json_resp(200, r#"{"id":1,"email":"alice@a.test","ts":"10:00:01","csrf":"x1"}"#);
        let b = json_resp(200, r#"{"id":1,"email":"alice@a.test","ts":"10:00:02","csrf":"x2"}"#);
        let noise = Noise::learn(&a, &b);
        let c = json_resp(200, r#"{"id":1,"email":"alice@a.test","ts":"11:11:11","csrf":"zz"}"#);
        assert_eq!(similarity(&a, &c, &noise), 1.0);
        let other = json_resp(200, r#"{"id":2,"email":"bob@a.test","ts":"11:11:11","csrf":"zz"}"#);
        assert_eq!(similarity(&a, &other, &noise), 0.0);
    }

    #[test]
    fn private_values_skip_public_and_request_values() {
        let base = json_resp(200, r#"{"id":17,"owner":"alice","email":"alice@a.test","site":"Shop","paid":true}"#);
        let noise = Noise::default();
        let anon = "<h1>Shop</h1>";
        let request = "GET /api/orders/17 HTTP/1.1";
        let mut p = private_values(&base, &noise, &[request, anon]);
        p.sort();
        assert_eq!(
            p,
            vec![("email".to_string(), "alice@a.test".to_string()), ("owner".to_string(), "alice".to_string())]
        );
        let leak = json_resp(200, r#"{"id":17,"owner":"alice","email":"alice@a.test","site":"Shop","paid":true}"#);
        assert_eq!(private_hits(&p, &leak), 2);
        let own = json_resp(200, r#"{"id":18,"owner":"bob","email":"bob@a.test","site":"Shop","paid":true}"#);
        assert_eq!(private_hits(&p, &own), 0);
        assert_eq!(private_hits(&p, &html_resp("<p>alice@a.test</p>")), 1);
    }

    #[test]
    fn text_similarity_and_words() {
        let noise = Noise::default();
        let a = html_resp("<p>Hello alice, your order 17 shipped</p>");
        assert_eq!(similarity(&a, &a, &noise), 1.0);
        let b = html_resp("<p>Hello bob, your order 18 shipped</p>");
        let s = similarity(&a, &b, &noise);
        assert!(s > 0.6 && s < 1.0, "{s}");
        assert_eq!(similarity(&a, &json_resp(200, "{}"), &noise), 0.0);
        assert!(mentions("id=alice;", "alice"));
        assert!(!mentions("malice", "alice"));
        assert!(mentions("to: alice@a.test.", "alice@a.test"));
    }

    #[test]
    fn object_references_and_denials() {
        assert!(references_object("/api/orders/17", ""));
        assert!(references_object("/doc?id=3f2b8a90-1c2d-4e5f-8a9b-0c1d2e3f4a5b", ""));
        assert!(references_object("/profile", r#"{"email":"bob@a.test"}"#));
        assert!(!references_object("/api/v2/dashboard", ""));
        assert!(!references_object("/account?tab=settings", ""));
        assert!(says_denied("Error: Access Denied"));
        assert!(!says_denied("Welcome back"));
        assert!(privileged_path("/admin/users"));
        assert!(privileged_path("/api/users"));
        assert!(!privileged_path("/api/userscript.js"));
    }
}
