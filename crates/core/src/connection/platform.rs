//! Platform authentication: HTTP Basic, Digest (RFC 7616: MD5, SHA-256, and their
//! -sess variants, qop auth), and NTLM (NTLMv2). Credentials come from auth
//! profiles that have a `platform` section; the client answers a 401 challenge of
//! the profile's scheme from a matching host, on every command (no `--auth`
//! needed). The header is added on the wire only: history records the request as
//! it was given, so the credentials never reach it.

use std::collections::HashMap;

use base64::Engine;
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::AuthProfile;
use crate::connection::HostPattern;
use crate::error::{Error, Result};
use crate::http::parse_response_head;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PlatformScheme {
    Basic,
    Digest,
    Ntlm,
}

impl PlatformScheme {
    pub const ALL: &'static [&'static str] = &["basic", "digest", "ntlm"];

    pub fn parse(s: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_ascii_lowercase()))
            .map_err(|_| Error::InvalidInput(format!("unknown platform scheme {s:?}; valid: basic, digest, ntlm")))
    }

    fn name(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Digest => "digest",
            Self::Ntlm => "ntlm",
        }
    }
}

/// The `platform` section of an auth profile. The username and password are the
/// profile's.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlatformAuth {
    pub scheme: PlatformScheme,
    /// Host patterns the credentials are offered to (see [`HostPattern`]).
    pub hosts: Vec<String>,
    /// NTLM domain; else taken from a `DOMAIN\user` username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

impl PlatformAuth {
    pub fn validate(&self) -> Result<()> {
        if self.hosts.is_empty() {
            return Err(Error::InvalidInput("platform authentication needs at least one --platform-host".into()));
        }
        for h in &self.hosts {
            HostPattern::parse(h)?;
        }
        Ok(())
    }
}

/// Platform credentials ready to use.
#[derive(Debug)]
pub struct PlatformCred {
    pub profile: String,
    pub scheme: PlatformScheme,
    hosts: Vec<HostPattern>,
    username: String,
    domain: String,
    /// The password, or why it isn't available (variable unset).
    password: std::result::Result<String, String>,
}

impl PlatformCred {
    /// The credentials of a profile with a platform section.
    pub fn from_profile(p: &AuthProfile) -> Option<Result<Self>> {
        let platform = p.platform.as_ref()?;
        Some((|| {
            let hosts = platform.hosts.iter().map(|h| HostPattern::parse(h)).collect::<Result<Vec<_>>>()?;
            let raw_user = p.username.clone().unwrap_or_default();
            let (domain, username) = match (&platform.domain, raw_user.split_once('\\')) {
                (Some(d), _) => (d.clone(), raw_user.rsplit('\\').next().unwrap_or_default().to_string()),
                (None, Some((d, u))) => (d.to_string(), u.to_string()),
                (None, None) => (String::new(), raw_user.clone()),
            };
            let password = match &p.password {
                Some(s) => s.resolve().map_err(|e| e.to_string()),
                None => Ok(String::new()),
            };
            Ok(Self { profile: p.name.clone(), scheme: platform.scheme, hosts, username, domain, password })
        })())
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        self.hosts.iter().any(|h| h.matches(host, port))
    }

    fn password(&self) -> Result<&str> {
        self.password
            .as_deref()
            .map_err(|e| Error::InvalidInput(format!("platform auth profile {:?}: {e}", self.profile)))
    }

    /// `Authorization` value for Basic.
    pub fn basic(&self) -> Result<String> {
        let user =
            if self.domain.is_empty() { self.username.clone() } else { format!("{}\\{}", self.domain, self.username) };
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{}", self.password()?));
        Ok(format!("Basic {token}"))
    }

    /// `Authorization` value answering a Digest challenge for one request.
    pub fn digest(&self, ch: &DigestChallenge, method: &str, uri: &str, nc: u32, cnonce: &str) -> Result<String> {
        let user =
            if self.domain.is_empty() { self.username.clone() } else { format!("{}\\{}", self.domain, self.username) };
        Ok(ch.answer(&user, self.password()?, method, uri, nc, cnonce))
    }

    /// The NTLM NEGOTIATE message, as an `Authorization` value.
    pub fn ntlm_negotiate(&self) -> String {
        format!("NTLM {}", base64::engine::general_purpose::STANDARD.encode(ntlm::negotiate()))
    }

    /// The NTLM AUTHENTICATE message answering a CHALLENGE, as an `Authorization` value.
    pub fn ntlm_authenticate(&self, challenge: &[u8]) -> Result<String> {
        let mut client_challenge = [0u8; 8];
        getrandom::fill(&mut client_challenge).map_err(|e| Error::Protocol(format!("random: {e}")))?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let filetime = (now.as_secs() + 11_644_473_600) * 10_000_000 + u64::from(now.subsec_nanos() / 100);
        let msg =
            ntlm::authenticate(challenge, &self.username, &self.domain, self.password()?, client_challenge, filetime)?;
        Ok(format!("NTLM {}", base64::engine::general_purpose::STANDARD.encode(msg)))
    }

    pub fn scheme_name(&self) -> &'static str {
        self.scheme.name()
    }
}

/// One challenge from a `WWW-Authenticate` header.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Challenge {
    /// Lowercase scheme name.
    pub scheme: String,
    pub token68: Option<String>,
    pub params: HashMap<String, String>,
}

/// The challenges of the final response's `WWW-Authenticate` headers.
pub fn challenges(response: &[u8]) -> Vec<Challenge> {
    let Ok(head) = parse_response_head(crate::http::client::final_response(response)) else { return vec![] };
    let mut out = Vec::new();
    for (k, v) in &head.headers {
        if k.eq_ignore_ascii_case("www-authenticate") {
            parse_challenges(v, &mut out);
        }
    }
    out
}

/// Splits on commas outside quoted strings.
fn split_items(v: &str) -> Vec<String> {
    let (mut items, mut cur, mut quoted, mut escaped) = (Vec::new(), String::new(), false, false);
    for c in v.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            ',' if !quoted => items.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    items.push(cur);
    items.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// `name=value` rather than a token68 (which only ends with '=').
fn is_param(s: &str) -> bool {
    let t = s.trim_end_matches('=');
    let token68 = !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || "-._~+/".contains(c));
    !token68 && s.split_once('=').is_some_and(|(n, _)| !n.trim().is_empty() && !n.trim().contains(char::is_whitespace))
}

pub(crate) fn parse_challenges(v: &str, out: &mut Vec<Challenge>) {
    for item in split_items(v) {
        let (first, rest) = match item.split_once(char::is_whitespace) {
            Some((a, b)) => (a, b.trim()),
            None => (item.as_str(), ""),
        };
        if first.contains('=') {
            // A parameter of the current challenge.
            if let Some(ch) = out.last_mut() {
                add_param(ch, &item);
            }
            continue;
        }
        let mut ch = Challenge { scheme: first.to_ascii_lowercase(), ..Default::default() };
        if !rest.is_empty() {
            if is_param(rest) {
                add_param(&mut ch, rest);
            } else {
                ch.token68 = Some(rest.to_string());
            }
        }
        out.push(ch);
    }
}

fn add_param(ch: &mut Challenge, item: &str) {
    let Some((k, v)) = item.split_once('=') else { return };
    let v = v.trim();
    let v = match v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        Some(inner) => {
            let mut s = String::new();
            let mut esc = false;
            for c in inner.chars() {
                if esc || c != '\\' {
                    s.push(c);
                    esc = false;
                } else {
                    esc = true;
                }
            }
            s
        }
        None => v.to_string(),
    };
    ch.params.insert(k.trim().to_ascii_lowercase(), v);
}

/// A Digest challenge we can answer.
#[derive(Debug, Clone, PartialEq)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    /// Upper case: MD5, MD5-SESS, SHA-256, SHA-256-SESS.
    pub algorithm: String,
    /// "auth", or none for the RFC 2069 form.
    pub qop: Option<String>,
    pub stale: bool,
}

impl DigestChallenge {
    /// The strongest Digest challenge offered that we support.
    pub fn pick(challenges: &[Challenge]) -> Option<Self> {
        let mut best: Option<Self> = None;
        for c in challenges.iter().filter(|c| c.scheme == "digest") {
            let algorithm = c.params.get("algorithm").map(|a| a.to_ascii_uppercase()).unwrap_or_else(|| "MD5".into());
            if !matches!(algorithm.as_str(), "MD5" | "MD5-SESS" | "SHA-256" | "SHA-256-SESS") {
                continue;
            }
            let qop = match c.params.get("qop") {
                None => None,
                // Only qop=auth: auth-int would need the body hashed as sent.
                Some(q) if q.split(',').any(|q| q.trim().eq_ignore_ascii_case("auth")) => Some("auth".to_string()),
                Some(_) => continue,
            };
            let (Some(realm), Some(nonce)) = (c.params.get("realm"), c.params.get("nonce")) else { continue };
            let ch = Self {
                realm: realm.clone(),
                nonce: nonce.clone(),
                opaque: c.params.get("opaque").cloned(),
                stale: c.params.get("stale").is_some_and(|s| s.eq_ignore_ascii_case("true")),
                algorithm,
                qop,
            };
            if best.as_ref().is_none_or(|b| !b.algorithm.starts_with("SHA") && ch.algorithm.starts_with("SHA")) {
                best = Some(ch);
            }
        }
        best
    }

    fn h(&self, s: &str) -> String {
        if self.algorithm.starts_with("SHA-256") {
            hex::encode(Sha256::digest(s.as_bytes()))
        } else {
            hex::encode(Md5::digest(s.as_bytes()))
        }
    }

    pub fn answer(&self, user: &str, password: &str, method: &str, uri: &str, nc: u32, cnonce: &str) -> String {
        let mut ha1 = self.h(&format!("{user}:{}:{password}", self.realm));
        if self.algorithm.ends_with("-SESS") {
            ha1 = self.h(&format!("{ha1}:{}:{cnonce}", self.nonce));
        }
        let ha2 = self.h(&format!("{method}:{uri}"));
        let nc = format!("{nc:08x}");
        let response = match &self.qop {
            Some(qop) => self.h(&format!("{ha1}:{}:{nc}:{cnonce}:{qop}:{ha2}", self.nonce)),
            None => self.h(&format!("{ha1}:{}:{ha2}", self.nonce)),
        };
        let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let mut out = format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", algorithm={}, response=\"{response}\"",
            q(user),
            q(&self.realm),
            q(&self.nonce),
            q(uri),
            self.algorithm
        );
        if let Some(qop) = &self.qop {
            out.push_str(&format!(", qop={qop}, nc={nc}, cnonce=\"{}\"", q(cnonce)));
        }
        if let Some(o) = &self.opaque {
            out.push_str(&format!(", opaque=\"{}\"", q(o)));
        }
        out
    }
}

/// The NTLM CHALLENGE message of a 401, if there is one.
pub fn ntlm_challenge(challenges: &[Challenge]) -> Option<Vec<u8>> {
    let token = challenges.iter().find(|c| c.scheme == "ntlm")?.token68.as_deref()?;
    base64::engine::general_purpose::STANDARD.decode(token).ok()
}

/// A fresh client nonce for Digest.
pub fn cnonce() -> String {
    let mut b = [0u8; 12];
    let _ = getrandom::fill(&mut b);
    hex::encode(b)
}

pub(crate) mod ntlm {
    //! NTLM messages (MS-NLMP), NTLMv2 responses only.

    use md4::Md4;
    use md5::{Digest, Md5};

    use crate::error::{Error, Result};

    const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
    const UNICODE: u32 = 0x0000_0001;
    const KEY_EXCH: u32 = 0x4000_0000;
    const SIGN_SEAL: u32 = 0x0000_0010 | 0x0000_0020;
    const VERSION: u32 = 0x0200_0000;
    /// UNICODE, OEM, REQUEST_TARGET, NTLM, ALWAYS_SIGN, EXTENDED_SESSIONSECURITY,
    /// TARGET_INFO, 128, 56.
    const FLAGS: u32 = 0xa088_8207;
    const AV_TIMESTAMP: u16 = 7;

    pub fn negotiate() -> Vec<u8> {
        let mut m = SIGNATURE.to_vec();
        m.extend_from_slice(&1u32.to_le_bytes());
        m.extend_from_slice(&FLAGS.to_le_bytes());
        // Empty domain and workstation fields.
        m.extend_from_slice(&[0u8; 16]);
        m
    }

    pub(crate) fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..16].copy_from_slice(&Md5::digest(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner = Md5::new();
        inner.update(k.map(|b| b ^ 0x36));
        for p in parts {
            inner.update(p);
        }
        let mut outer = Md5::new();
        outer.update(k.map(|b| b ^ 0x5c));
        outer.update(inner.finalize());
        outer.finalize().into()
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    pub(crate) fn nt_hash(password: &str) -> [u8; 16] {
        Md4::digest(utf16(password)).into()
    }

    pub(crate) fn ntowf_v2(password: &str, user: &str, domain: &str) -> [u8; 16] {
        hmac_md5(&nt_hash(password), &[&utf16(&(user.to_uppercase() + domain))])
    }

    struct Challenge<'a> {
        flags: u32,
        server_challenge: [u8; 8],
        target_info: &'a [u8],
    }

    fn field(msg: &[u8], at: usize) -> Option<&[u8]> {
        let len = u16::from_le_bytes(msg.get(at..at + 2)?.try_into().ok()?) as usize;
        let off = u32::from_le_bytes(msg.get(at + 4..at + 8)?.try_into().ok()?) as usize;
        if len == 0 {
            return Some(&[]);
        }
        msg.get(off..off.checked_add(len)?)
    }

    fn parse_challenge(msg: &[u8]) -> Option<Challenge<'_>> {
        if msg.get(..8)? != SIGNATURE || msg.get(8..12)? != 2u32.to_le_bytes() {
            return None;
        }
        Some(Challenge {
            flags: u32::from_le_bytes(msg.get(20..24)?.try_into().ok()?),
            server_challenge: msg.get(24..32)?.try_into().ok()?,
            target_info: if msg.len() >= 48 { field(msg, 40)? } else { &[] },
        })
    }

    /// The server's timestamp from the target info (MsvAvTimestamp), if any.
    fn av_timestamp(info: &[u8]) -> Option<[u8; 8]> {
        let mut i = 0;
        while i + 4 <= info.len() {
            let id = u16::from_le_bytes([info[i], info[i + 1]]);
            let len = u16::from_le_bytes([info[i + 2], info[i + 3]]) as usize;
            if id == 0 {
                return None;
            }
            let value = info.get(i + 4..i + 4 + len)?;
            if id == AV_TIMESTAMP {
                return value.try_into().ok();
            }
            i += 4 + len;
        }
        None
    }

    /// The NTLMv2 and LMv2 responses (MS-NLMP 3.3.2) for a server challenge.
    pub(crate) fn responses(
        key: &[u8; 16],
        server_challenge: &[u8; 8],
        client_challenge: &[u8; 8],
        time: [u8; 8],
        target_info: &[u8],
        lm_zero: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut temp = vec![1u8, 1, 0, 0, 0, 0, 0, 0];
        temp.extend_from_slice(&time);
        temp.extend_from_slice(client_challenge);
        temp.extend_from_slice(&[0u8; 4]);
        temp.extend_from_slice(target_info);
        temp.extend_from_slice(&[0u8; 4]);
        let proof = hmac_md5(key, &[server_challenge, &temp]);
        let mut nt = proof.to_vec();
        nt.extend_from_slice(&temp);
        let lm = if lm_zero {
            vec![0u8; 24]
        } else {
            let mut lm = hmac_md5(key, &[server_challenge, client_challenge]).to_vec();
            lm.extend_from_slice(client_challenge);
            lm
        };
        (nt, lm)
    }

    pub fn authenticate(
        challenge: &[u8],
        user: &str,
        domain: &str,
        password: &str,
        client_challenge: [u8; 8],
        filetime: u64,
    ) -> Result<Vec<u8>> {
        let ch =
            parse_challenge(challenge).ok_or_else(|| Error::Protocol("bad NTLM challenge from the server".into()))?;
        let server_time = av_timestamp(ch.target_info);
        let time = server_time.unwrap_or(filetime.to_le_bytes());
        let key = ntowf_v2(password, user, domain);
        let (nt, lm) =
            responses(&key, &ch.server_challenge, &client_challenge, time, ch.target_info, server_time.is_some());
        let unicode = ch.flags & UNICODE != 0;
        let text = |s: &str| if unicode { utf16(s) } else { s.as_bytes().to_vec() };
        let flags = (ch.flags & FLAGS) & !(KEY_EXCH | SIGN_SEAL | VERSION);
        let payload: [Vec<u8>; 5] = [lm, nt, text(domain), text(user), text("")];
        let mut msg = SIGNATURE.to_vec();
        msg.extend_from_slice(&3u32.to_le_bytes());
        let mut offset = 64u32;
        let mut field = |msg: &mut Vec<u8>, len: usize| {
            msg.extend_from_slice(&(len as u16).to_le_bytes());
            msg.extend_from_slice(&(len as u16).to_le_bytes());
            msg.extend_from_slice(&offset.to_le_bytes());
            offset += len as u32;
        };
        for p in &payload {
            field(&mut msg, p.len());
        }
        // No session key: neither signing nor sealing is used over HTTP.
        field(&mut msg, 0);
        msg.extend_from_slice(&flags.to_le_bytes());
        for p in &payload {
            msg.extend_from_slice(p);
        }
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_challenges() {
        let mut out = Vec::new();
        parse_challenges(
            "Negotiate, NTLM, Digest realm=\"a, b\", nonce=\"n\\\"1\", qop=\"auth,auth-int\", Basic realm=x",
            &mut out,
        );
        let schemes: Vec<&str> = out.iter().map(|c| c.scheme.as_str()).collect();
        assert_eq!(schemes, ["negotiate", "ntlm", "digest", "basic"]);
        assert_eq!(out[2].params["realm"], "a, b");
        assert_eq!(out[2].params["nonce"], "n\"1");
        assert_eq!(out[2].params["qop"], "auth,auth-int");
        let mut out = Vec::new();
        parse_challenges("NTLM TlRMTVNTUAACAAAAAAA=", &mut out);
        assert_eq!(out[0].token68.as_deref(), Some("TlRMTVNTUAACAAAAAAA="));
    }

    #[test]
    fn digest_matches_rfc_7616() {
        // RFC 7616 3.9.1.
        let mut out = Vec::new();
        parse_challenges(
            "Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=MD5, \
             nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", \
             opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"",
            &mut out,
        );
        let ch = DigestChallenge::pick(&out).unwrap();
        let cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
        let h = ch.answer("Mufasa", "Circle of Life", "GET", "/dir/index.html", 1, cnonce);
        assert!(h.contains("response=\"8ca523f5e9506fed4657c9700eebdbec\""), "{h}");
        assert!(h.contains("qop=auth, nc=00000001") && h.contains("opaque=\"FQhe"));
        let sha = DigestChallenge { algorithm: "SHA-256".into(), ..ch };
        let h = sha.answer("Mufasa", "Circle of Life", "GET", "/dir/index.html", 1, cnonce);
        assert!(h.contains("753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"), "{h}");
        // SHA-256 is preferred over MD5 when both are offered.
        let mut both = Vec::new();
        parse_challenges(
            "Digest realm=r, nonce=n, algorithm=MD5, Digest realm=r, nonce=n, algorithm=SHA-256",
            &mut both,
        );
        assert_eq!(DigestChallenge::pick(&both).unwrap().algorithm, "SHA-256");
    }

    #[test]
    fn ntlmv2_matches_ms_nlmp() {
        // MS-NLMP 4.2.2.1.2 and 4.2.4: User / Domain / Password.
        assert_eq!(hex::encode(ntlm::nt_hash("Password")), "a4f49c406510bdcab6824ee7c30fd852");
        let key = ntlm::ntowf_v2("Password", "User", "Domain");
        assert_eq!(hex::encode(key), "0c868a403bfd7a93a3001ef22ef02e3f");
        let info = hex::decode("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000").unwrap();
        let server: [u8; 8] = hex::decode("0123456789abcdef").unwrap().try_into().unwrap();
        let (nt, lm) = ntlm::responses(&key, &server, &[0xaa; 8], [0; 8], &info, false);
        assert_eq!(hex::encode(&nt[..16]), "68cd0ab851e51c96aabc927bebef6a1c");
        assert_eq!(hex::encode(lm), "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa");
    }
}
