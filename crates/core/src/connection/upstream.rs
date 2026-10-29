//! Upstream proxies: HTTP CONNECT and SOCKS5 (RFC 1928, with RFC 1929
//! username/password). The proxy is always asked for the address the scope
//! guard checked, never the name, so it can't resolve the name somewhere else.
//! The trade-off: proxies that filter or log by host name see an IP address, and
//! plain-HTTP targets go through a CONNECT tunnel too (so a proxy that only allows
//! CONNECT to port 443 can't carry them).

use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Http,
    Socks5,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamProxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password_env: Option<String>,
}

/// Longest CONNECT response head we read.
const MAX_HEAD: usize = 16 * 1024;

impl UpstreamProxy {
    /// Parses `http://HOST:PORT` or `socks5://HOST:PORT` (`socks5h` is refused: the
    /// proxy must not resolve names).
    pub fn parse(url: &str, username: Option<String>, password_env: Option<String>) -> Result<Self> {
        let bad = |why: &str| Error::InvalidInput(format!("bad upstream proxy {url:?}: {why}"));
        let u = url::Url::parse(url).map_err(|e| bad(&e.to_string()))?;
        let kind = match u.scheme() {
            "http" => ProxyKind::Http,
            "socks5" => ProxyKind::Socks5,
            "socks5h" => {
                return Err(bad(
                    "socks5h lets the proxy resolve names; use socks5 (brainproxy resolves and checks them)",
                ))
            }
            _ => return Err(bad("use http://HOST:PORT or socks5://HOST:PORT")),
        };
        if !u.username().is_empty() || u.password().is_some() {
            return Err(bad("give the user with --username and the password with --password-env, not in the URL"));
        }
        if u.path() != "/" && !u.path().is_empty() || u.query().is_some() {
            return Err(bad("no path or query"));
        }
        let host =
            u.host_str().ok_or_else(|| bad("no host"))?.trim_start_matches('[').trim_end_matches(']').to_string();
        // `url` drops a default port (http://x:80 has no port), so http defaults to 80.
        let port = u.port_or_known_default().unwrap_or(1080);
        if password_env.is_some() && username.is_none() {
            return Err(bad("a password needs a --username"));
        }
        Ok(Self { kind, host, port, username, password_env })
    }

    pub fn url(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let scheme = match self.kind {
            ProxyKind::Http => "http",
            ProxyKind::Socks5 => "socks5",
        };
        format!("{scheme}://{host}:{}", self.port)
    }

    fn credentials(&self) -> Result<Option<(String, String)>> {
        let Some(user) = &self.username else { return Ok(None) };
        let password = match &self.password_env {
            Some(var) => std::env::var(var)
                .map_err(|_| Error::InvalidInput(format!("upstream proxy password variable {var} is not set")))?,
            None => String::new(),
        };
        Ok(Some((user.clone(), password)))
    }

    /// Connects to the proxy (at one of `proxy_addrs`, already checked) and has it
    /// open a tunnel to `target`. Returns the socket, ready for the target's bytes.
    pub async fn open(&self, proxy_addrs: &[SocketAddr], target: SocketAddr) -> Result<TcpStream> {
        let creds = self.credentials()?;
        let fail = |e: String| Error::Connect(format!("upstream proxy {}: {e}", self.url()));
        let mut tcp = TcpStream::connect(proxy_addrs).await.map_err(|e| fail(e.to_string()))?;
        tcp.set_nodelay(true).ok();
        match self.kind {
            ProxyKind::Http => http_connect(&mut tcp, target, creds.as_ref()).await,
            ProxyKind::Socks5 => socks5_connect(&mut tcp, target, creds.as_ref()).await,
        }
        .map_err(|e| match e {
            Error::Io(io) => fail(io.to_string()),
            Error::Protocol(m) => fail(m),
            e => e,
        })?;
        Ok(tcp)
    }
}

async fn http_connect(tcp: &mut TcpStream, target: SocketAddr, creds: Option<&(String, String)>) -> Result<()> {
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some((u, p)) = creds {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes()).await?;
    // Read the response head byte by byte: whatever follows belongs to the target.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        if tcp.read(&mut b).await? == 0 {
            return Err(Error::Protocol("closed the connection during CONNECT".into()));
        }
        head.push(b[0]);
        if head.len() > MAX_HEAD {
            return Err(Error::Protocol("CONNECT response head too long".into()));
        }
    }
    let status_line = String::from_utf8_lossy(&head[..head.iter().position(|&b| b == b'\r').unwrap_or(0)]).into_owned();
    let status = status_line.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok());
    match status {
        Some(200..=299) => Ok(()),
        Some(407) => Err(Error::Protocol(format!(
            "asks for authentication ({status_line}){}",
            if creds.is_some() { "; the credentials were refused" } else { ": add --username/--password-env" }
        ))),
        _ => Err(Error::Protocol(format!("refused CONNECT {target}: {status_line}"))),
    }
}

async fn socks5_connect(tcp: &mut TcpStream, target: SocketAddr, creds: Option<&(String, String)>) -> Result<()> {
    let methods: &[u8] = if creds.is_some() { &[0x00, 0x02] } else { &[0x00] };
    let mut hello = vec![0x05, methods.len() as u8];
    hello.extend_from_slice(methods);
    tcp.write_all(&hello).await?;
    let mut choice = [0u8; 2];
    tcp.read_exact(&mut choice).await?;
    if choice[0] != 0x05 {
        return Err(Error::Protocol("is not a SOCKS5 proxy".into()));
    }
    match choice[1] {
        0x00 => {}
        0x02 => {
            let (u, p) = creds.ok_or_else(|| Error::Protocol("asked for a username and password".into()))?;
            if u.len() > 255 || p.len() > 255 {
                return Err(Error::InvalidInput("SOCKS5 username and password are at most 255 bytes".into()));
            }
            let mut auth = vec![0x01, u.len() as u8];
            auth.extend_from_slice(u.as_bytes());
            auth.push(p.len() as u8);
            auth.extend_from_slice(p.as_bytes());
            tcp.write_all(&auth).await?;
            let mut status = [0u8; 2];
            tcp.read_exact(&mut status).await?;
            if status[1] != 0x00 {
                return Err(Error::Protocol("refused the username and password".into()));
            }
        }
        0xff => {
            return Err(Error::Protocol(
                if creds.is_some() {
                    "accepts none of our authentication methods"
                } else {
                    "requires authentication: add --username/--password-env"
                }
                .into(),
            ))
        }
        m => return Err(Error::Protocol(format!("chose unsupported authentication method {m}"))),
    }
    let mut req = vec![0x05, 0x01, 0x00];
    match target.ip() {
        IpAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    tcp.write_all(&req).await?;
    let mut reply = [0u8; 4];
    tcp.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        let why = match reply[1] {
            0x01 => "general failure",
            0x02 => "not allowed by its rules",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(Error::Protocol(format!("could not connect to {target}: {why}")));
    }
    // The bound address, which we don't need.
    let rest = match reply[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        _ => return Err(Error::Protocol("bad SOCKS5 reply".into())),
    };
    let mut skip = vec![0u8; rest];
    tcp.read_exact(&mut skip).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proxy_urls() {
        let p = UpstreamProxy::parse("socks5://127.0.0.1", None, None).unwrap();
        assert_eq!((p.kind, p.port), (ProxyKind::Socks5, 1080));
        assert_eq!(UpstreamProxy::parse("http://127.0.0.1:80", None, None).unwrap().port, 80);
        assert_eq!(UpstreamProxy::parse("socks5://127.0.0.1:80", None, None).unwrap().port, 80);
        let p = UpstreamProxy::parse("http://[::1]:3128", Some("u".into()), Some("V".into())).unwrap();
        assert_eq!((p.kind, p.host.as_str(), p.url()), (ProxyKind::Http, "::1", "http://[::1]:3128".to_string()));
        for bad in ["socks5h://x:1", "ftp://x", "http://u:p@x:1", "http://x:1/path", "nonsense"] {
            assert!(UpstreamProxy::parse(bad, None, None).is_err(), "{bad}");
        }
        assert!(UpstreamProxy::parse("http://x:1", None, Some("V".into())).is_err());
    }
}
