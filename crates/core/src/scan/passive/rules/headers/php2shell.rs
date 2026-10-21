//! PHP2Shell (CVE-2026-109618, CVE-2026-109619): a PHP version from response headers.
//! brainproxy's own rule, not a ZAP port. Like Heartbleed (10034) it only reads the version
//! the server reports; it never sends the multipart request that triggers the bug.

use std::sync::LazyLock;

use regex::Regex;

use super::common::headers_block;
use crate::scan::{AlertDef, Confidence, Finding, Message, PassiveRule, Risk};

static ALERT: AlertDef = AlertDef {
    alert_ref: "100001",
    name: "PHP2Shell PHP Remote Code Execution (Indicative)",
    risk: Risk::High,
    confidence: Confidence::Low,
    cwe: 416,
    wasc: 20,
    description: "The server reports a PHP version affected by PHP2Shell (CVE-2026-109618, CVE-2026-109619). Two \
        use-after-free bugs in PHP's request handling let an unauthenticated attacker run code on the server with a \
        crafted multipart/form-data request, which PHP parses before any application code runs. Default \
        configurations of Apache mod_php and PHP-FPM are affected, from PHP 5.4 on. Exploit tools are public.",
    solution: "Update PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 or later. PHP 8.1 and older get no official release: \
        upgrade, or install your vendor's backported fix. Until then, set session.upload_progress.enabled = 0, and \
        block multipart/form-data requests where the application doesn't need uploads.",
    references: &[
        "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
        "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
        "https://www.php.net/archive/2026.php",
    ],
    tags: &["OWASP_2025_A03", "OWASP_2021_A06", "OWASP_2017_A09", "CVE-2026-109618", "CVE-2026-109619"],
};

static ALERTS: [&AlertDef; 1] = [&ALERT];

// X-Powered-By: PHP/8.2.20, Server: Apache/2.4.57 (Debian) PHP/8.1.2-1ubuntu2.14
static PHP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:X-Powered-By|Server):[^\r\n]*?\b(PHP/(\d+)\.(\d+)\.(\d+)\S*)").unwrap());

/// First fixed release per branch (21 Oct 2026). Branches 5.4 to 8.1 have none.
const FIXED: &[((u32, u32), u32)] = &[((8, 2), 35), ((8, 3), 36), ((8, 4), 27), ((8, 5), 12)];

fn vulnerable(major: u32, minor: u32, patch: u32) -> bool {
    if (major, minor) < (5, 4) {
        return false;
    }
    match FIXED.iter().find(|(b, _)| *b == (major, minor)) {
        Some((_, fixed)) => patch < *fixed,
        None => (major, minor) < (8, 2),
    }
}

pub struct Php2Shell;

impl PassiveRule for Php2Shell {
    fn id(&self) -> u32 {
        100001
    }

    fn name(&self) -> &'static str {
        "PHP2Shell PHP Remote Code Execution (Indicative)"
    }

    fn alerts(&self) -> &'static [&'static AlertDef] {
        &ALERTS
    }

    fn scan(&self, msg: &Message, out: &mut Vec<Finding>) {
        if !msg.resp_headers.iter().any(|(_, v)| v.as_bytes().windows(4).any(|w| w.eq_ignore_ascii_case(b"php/"))) {
            return;
        }
        for line in headers_block(msg).split("\r\n") {
            let Some(c) = PHP.captures(line) else { continue };
            let n = |i: usize| c[i].parse::<u32>().unwrap_or(0);
            if vulnerable(n(2), n(3), n(4)) {
                let full = &c[1];
                out.push(ALERT.raise("", full).other_info(format!(
                    "{full} is in use. The reported version could contain back-ported security fixes (Debian, \
                     Ubuntu, Red Hat and other distributions keep the upstream number), so check the installed \
                     package before reporting this as vulnerable."
                )));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::passive::util::testing::msg;

    #[test]
    fn flags_affected_versions() {
        let f = msg("https://a.test/").header("X-Powered-By", "PHP/8.2.34").scan(&Php2Shell);
        assert_eq!((f.len(), f[0].evidence.as_str()), (1, "PHP/8.2.34"));
        assert!(f[0].other_info.starts_with("PHP/8.2.34 is in use."));
        let f =
            msg("https://a.test/").header("Server", "Apache/2.4.57 (Ubuntu) PHP/8.1.2-1ubuntu2.14").scan(&Php2Shell);
        assert_eq!(f[0].evidence, "PHP/8.1.2-1ubuntu2.14");
        for v in ["5.4.0", "7.4.33", "8.0.30", "8.3.35", "8.4.26", "8.5.11"] {
            assert_eq!(
                msg("https://a.test/").header("X-Powered-By", &format!("PHP/{v}")).scan(&Php2Shell).len(),
                1,
                "{v}"
            );
        }
    }

    #[test]
    fn ignores_fixed_unaffected_and_other_headers() {
        for v in ["5.3.29", "8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.5.13", "8.6.0", "9.0.0"] {
            assert!(
                msg("https://a.test/").header("X-Powered-By", &format!("PHP/{v}")).scan(&Php2Shell).is_empty(),
                "{v}"
            );
        }
        assert!(msg("https://a.test/").header("X-Lib", "PHP/8.2.1").scan(&Php2Shell).is_empty());
        assert!(msg("https://a.test/").header("X-Powered-By", "PHP/8").scan(&Php2Shell).is_empty());
        assert!(msg("https://a.test/").header("X-Powered-By", "Express").scan(&Php2Shell).is_empty());
    }
}
