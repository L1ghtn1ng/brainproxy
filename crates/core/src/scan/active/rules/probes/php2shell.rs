//! PHP2Shell (CVE-2026-109618, CVE-2026-109619): sites that run PHP, also when they hide the version.
//! brainproxy's own rule, not a ZAP port. Nothing here triggers the bug (that needs a request that
//! exhausts memory_limit); it fingerprints PHP and checks whether multipart requests reach it.

use super::common::{base_path_query, is_page_200, with_body, with_request_line};
use crate::http::RawRequest;
use crate::scan::active::{rand_u64, ActiveRule, BoxFuture, Cx, Response, RuleScope};
use crate::scan::passive::rules::headers::php2shell::reported_php;
use crate::scan::{AlertDef, Confidence, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "100002",
    name: "PHP2Shell PHP Remote Code Execution (Suspected)",
    risk: Risk::High,
    confidence: Confidence::Low,
    cwe: 416,
    wasc: 20,
    description: "The site runs PHP, and its version is either hidden or affected by PHP2Shell (CVE-2026-109618, \
        CVE-2026-109619). Two use-after-free bugs in PHP's request handling let an unauthenticated attacker run code \
        on the server with a crafted multipart/form-data request, which PHP parses before any application code runs. PHP \
        5.4 and later are affected. Code execution is confirmed on Apache mod_php with default settings; PHP-FPM, \
        FrankenPHP and LiteSpeed are likely affected, depending on configuration. Proof-of-concept code circulates.",
    solution: "Check the PHP version on the server. Update to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 or later; PHP 8.1 and \
        older get no official release, so upgrade or install your vendor's backported fix. Until then, these reduce \
        exposure but don't make PHP safe: set session.upload_progress.enabled = 0 and memory_limit = -1 (php.ini, \
        php_admin_value or the FPM pool, not ini_set or .user.ini), lower post_max_size, restart every worker, and \
        block multipart/form-data requests where the application doesn't need uploads.",
    references: &[
        "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
        "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
        "https://www.php.net/archive/2026.php",
    ],
    tags: &["OWASP_2025_A03", "OWASP_2021_A06", "OWASP_2017_A09", "CVE-2026-109618", "CVE-2026-109619"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

/// Bodies the PHP-FPM / CGI handler sends for a .php file that doesn't exist.
const HANDLER_MISSING: &[&str] = &["No input file specified.", "Primary script unknown"];

/// What one response says about PHP: header signs, and the reported version if any.
fn php_signs(resp: &Response) -> (Vec<String>, Option<(String, bool)>) {
    let mut signs = Vec::new();
    let version = reported_php(&resp.headers);
    if version.is_none() && resp.headers_named("X-Powered-By").any(|v| v.trim().to_ascii_lowercase().starts_with("php"))
    {
        signs.push("X-Powered-By: PHP".to_string());
    }
    if resp.headers_named("Set-Cookie").any(|v| v.trim_start().to_ascii_uppercase().starts_with("PHPSESSID=")) {
        signs.push("a PHPSESSID cookie".to_string());
    }
    (signs, version)
}

fn handler_missing(resp: &Response) -> bool {
    let body = resp.body_str();
    HANDLER_MISSING.iter().any(|s| body.contains(s)) || (resp.status == 404 && body.trim() == "File not found.")
}

/// A 403, 406, 415 or 501 to a multipart POST, or no response, looks like a filter.
fn multipart_blocked(resp: Option<&Response>) -> bool {
    resp.is_none_or(|r| matches!(r.status, 403 | 406 | 415 | 501))
}

fn note(
    signs: &mut Vec<String>,
    version: &mut Option<(String, bool)>,
    what: &str,
    s: Vec<String>,
    v: Option<(String, bool)>,
) {
    if !s.is_empty() {
        signs.push(format!("{what}: {}", s.join(", ")));
    }
    if let Some(v) = v {
        signs.push(format!("{what}: {}", v.0));
        version.get_or_insert(v);
    }
}

pub struct Php2Shell;

impl ActiveRule for Php2Shell {
    fn id(&self) -> u32 {
        100002
    }

    fn name(&self) -> &'static str {
        "PHP2Shell PHP Remote Code Execution (Suspected)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scope(&self) -> RuleScope {
        RuleScope::Host
    }

    fn scan<'a>(&'a self, cx: &'a Cx) -> BoxFuture<'a> {
        Box::pin(async move {
            if cx.stopped() {
                return;
            }
            let mut signs = Vec::new();
            let mut version = None;
            let mut proof: Option<Response> = None;

            let base = cx.base_response().clone();
            let (s, v) = php_signs(&base);
            note(&mut signs, &mut version, &format!("{} {}", cx.base().method, cx.base().path), s, v);
            if cx.base().path.to_ascii_lowercase().ends_with(".php") {
                signs.push(format!("the page {} is a .php script", cx.base().path));
            }
            if !signs.is_empty() {
                proof = Some(base);
            }
            if let Ok(r) = cx.send(cx.request_for("GET", "/index.php")).await {
                if is_page_200(cx, &r).await {
                    let (mut s, v) = php_signs(&r);
                    s.insert(0, "200 OK".into());
                    note(&mut signs, &mut version, "GET /index.php", s, v);
                    proof.get_or_insert(r);
                }
            }
            let missing = format!("/brainproxy-{:x}.php", rand_u64());
            if let Ok(r) = cx.send(cx.request_for("GET", &missing)).await {
                let (mut s, v) = php_signs(&r);
                if handler_missing(&r) {
                    s.insert(0, format!("PHP handler error \"{}\"", r.body_str().trim().lines().next().unwrap_or("")));
                }
                if !s.is_empty() || v.is_some() {
                    note(&mut signs, &mut version, &format!("GET {missing}"), s, v);
                    proof.get_or_insert(r);
                }
            }

            match &version {
                Some((_, false)) => return, // a fixed version is reported
                None if signs.is_empty() => return,
                _ => {}
            }
            let Some(proof) = proof else { return };

            // A small multipart form, like any upload: does it reach PHP, or is it filtered?
            let boundary = format!("----brainproxy{:x}", rand_u64());
            let body = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"bp{:x}\"\r\n\r\n1\r\n--{boundary}--\r\n",
                rand_u64()
            );
            let raw = with_request_line(cx.base_request(), "POST", &base_path_query(cx));
            let raw = RawRequest::from_bytes(raw)
                .set_header("Content-Type", &format!("multipart/form-data; boundary={boundary}"))
                .into_bytes();
            let multipart = cx.send(with_body(raw, body.as_bytes())).await.ok();
            let blocked = multipart_blocked(multipart.as_ref());

            let evidence = match &version {
                Some((v, _)) => v.clone(),
                None => signs.first().cloned().unwrap_or_default(),
            };
            let mut info = match &version {
                Some((v, _)) => format!(
                    "{v} is reported, an affected version. Distributions back-port the fix without changing the \
                     version number, so check the installed package.\n"
                ),
                None => "PHP is in use but doesn't report its version, so it may be affected. Check the PHP version \
                         on the server.\n"
                    .to_string(),
            };
            info.push_str("\nSigns of PHP:\n");
            for s in &signs {
                info.push_str(&format!("- {s}\n"));
            }
            let path = base_path_query(cx);
            let tail = match (blocked, &multipart) {
                (true, Some(r)) => format!(
                    "\nA multipart/form-data POST to {path} got {}: multipart requests look filtered, the suggested \
                     stop-gap. Other paths may still accept them.",
                    r.status
                ),
                (true, None) => {
                    "\nA multipart/form-data POST got no response: multipart requests may be filtered.".into()
                }
                (false, Some(r)) => format!(
                    "\nA multipart/form-data POST to {path} got {}: multipart requests reach the server, so the attack \
                     path is open.",
                    r.status
                ),
                (false, None) => String::new(),
            };
            info.push_str(&tail);
            cx.report(
                ALERT.raise("", evidence).other_info(info),
                multipart.as_ref().filter(|_| !blocked).unwrap_or(&proof),
            );
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
        let mut raw = format!("HTTP/1.1 {status} X\r\n");
        for (k, v) in headers {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        Response::parse(Vec::new(), raw.into_bytes(), Default::default()).unwrap()
    }

    #[test]
    fn finds_php_signs() {
        let (s, v) = php_signs(&resp(200, &[("Set-Cookie", "PHPSESSID=abc; path=/")], ""));
        assert_eq!((s, v), (vec!["a PHPSESSID cookie".to_string()], None));
        let (s, v) = php_signs(&resp(200, &[("X-Powered-By", "PHP/8.3.10")], ""));
        assert_eq!((s.len(), v), (0, Some(("PHP/8.3.10".to_string(), true))));
        let (_, v) = php_signs(&resp(200, &[("X-Powered-By", "PHP/8.4.27")], ""));
        assert_eq!(v, Some(("PHP/8.4.27".to_string(), false)));
        assert_eq!(php_signs(&resp(200, &[("Set-Cookie", "sid=1"), ("Server", "nginx")], "")).0.len(), 0);
    }

    #[test]
    fn handler_and_filter() {
        assert!(handler_missing(&resp(404, &[], "No input file specified.\n")));
        assert!(handler_missing(&resp(404, &[], "File not found.\n")));
        assert!(!handler_missing(&resp(200, &[], "File not found.")));
        assert!(!handler_missing(&resp(404, &[], "<h1>Not Found</h1>")));
        assert!(multipart_blocked(None));
        assert!(multipart_blocked(Some(&resp(403, &[], ""))));
        assert!(!multipart_blocked(Some(&resp(200, &[], ""))));
        assert!(!multipart_blocked(Some(&resp(405, &[], ""))));
    }
}
