//! Connection options against local servers: an HTTP CONNECT and a SOCKS5 proxy,
//! a server that requires a client certificate (HTTP/1.1 and HTTP/2), and servers
//! that ask for Basic, Digest, and NTLM.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::guard::{Guard, ScopeSpec};
use crate::http::{Client, RawRequest, SendOptions, Target, WireReader};

fn spec(include: &[&str]) -> ScopeSpec {
    ScopeSpec { name: None, include: include.iter().map(|s| s.to_string()).collect(), exclude: vec![] }
}

fn client(guard: &Arc<Guard>) -> Client {
    Client::new(SendOptions { guard: Some(guard.clone()), ..Default::default() })
}

fn get(url: &str) -> (RawRequest, Target) {
    RawRequest::build("GET", url, &[], b"").unwrap()
}

fn body(response: &[u8]) -> String {
    let text = String::from_utf8_lossy(response);
    text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default()
}

/// Answers every request with 200 and the request's head as the body.
async fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut reader = WireReader::new();
                while let Ok(Some(req)) = reader.read_request(&mut s).await {
                    let head = crate::http::request::split_head_body(&req).0.to_vec();
                    let out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", head.len());
                    if s.write_all(out.as_bytes()).await.is_err() || s.write_all(&head).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

type Seen = Arc<Mutex<Vec<String>>>;

/// A CONNECT proxy that records the authority asked for and wants `auth` (user:password).
async fn connect_proxy(auth: Option<&'static str>) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut reader = WireReader::new();
                let Ok(Some(req)) = reader.read_request(&mut s).await else { return };
                let head = RawRequest::from_bytes(req).head().unwrap();
                log.lock().unwrap().push(head.target.clone());
                let given = head.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"));
                if let Some(want) = auth {
                    let expected = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(want));
                    if given.map(|(_, v)| v.as_str()) != Some(expected.as_str()) {
                        let _ = s
                            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
                            .await;
                        return;
                    }
                }
                let Ok(mut up) = TcpStream::connect(head.target.as_str()).await else { return };
                let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    (port, seen)
}

/// A SOCKS5 proxy (IPv4 CONNECT only) that records the address asked for and,
/// with `auth`, requires that username and password.
async fn socks_proxy(auth: Option<(&'static str, &'static str)>) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut hello = [0u8; 2];
                s.read_exact(&mut hello).await.unwrap();
                let mut methods = vec![0u8; hello[1] as usize];
                s.read_exact(&mut methods).await.unwrap();
                if let Some((u, p)) = auth {
                    if !methods.contains(&2) {
                        s.write_all(&[5, 0xff]).await.unwrap();
                        return;
                    }
                    s.write_all(&[5, 2]).await.unwrap();
                    let mut v = [0u8; 2];
                    s.read_exact(&mut v).await.unwrap();
                    let mut user = vec![0u8; v[1] as usize];
                    s.read_exact(&mut user).await.unwrap();
                    let mut plen = [0u8; 1];
                    s.read_exact(&mut plen).await.unwrap();
                    let mut pass = vec![0u8; plen[0] as usize];
                    s.read_exact(&mut pass).await.unwrap();
                    let ok = user == u.as_bytes() && pass == p.as_bytes();
                    s.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                    if !ok {
                        return;
                    }
                } else {
                    s.write_all(&[5, 0]).await.unwrap();
                }
                let mut req = [0u8; 4];
                s.read_exact(&mut req).await.unwrap();
                assert_eq!(req[3], 1, "the proxy is asked for an IPv4 address, never a name");
                let mut addr = [0u8; 6];
                s.read_exact(&mut addr).await.unwrap();
                let target =
                    SocketAddr::from(([addr[0], addr[1], addr[2], addr[3]], u16::from_be_bytes([addr[4], addr[5]])));
                log.lock().unwrap().push(target.to_string());
                let mut up = TcpStream::connect(target).await.unwrap();
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    (port, seen)
}

fn upstream(host: &str, proxy: &str, user: Option<&str>, env: Option<&str>) -> UpstreamRule {
    UpstreamRule {
        host: host.into(),
        proxy: Some(proxy.into()),
        username: user.map(str::to_string),
        password_env: env.map(str::to_string),
    }
}

#[tokio::test]
async fn http_connect_proxy_is_asked_for_the_checked_address() {
    let server = echo_server().await;
    let (proxy, seen) = connect_proxy(Some("alice:s3cret")).await;
    std::env::set_var("BP_TEST_HTTP_PROXY_PW", "s3cret");
    let g = Guard::from_specs(vec![spec(&["app.test", "127.0.0.1"])]).unwrap();
    let settings = ConnectionSettings {
        upstream: vec![upstream(
            "*",
            &format!("http://127.0.0.1:{proxy}"),
            Some("alice"),
            Some("BP_TEST_HTTP_PROXY_PW"),
        )],
        hosts: vec![HostOverride { host: "app.test".into(), ip: "127.0.0.1".parse().unwrap() }],
        ..Default::default()
    };
    g.net.set(settings.compile(vec![]).unwrap());
    let (req, target) = get(&format!("http://app.test:{server}/x"));
    let ex = client(&g).send(&req, &target).await.unwrap();
    // The proxy got the address, the server still the name.
    assert_eq!(*seen.lock().unwrap(), vec![format!("127.0.0.1:{server}")]);
    assert!(body(&ex.response).contains(&format!("Host: app.test:{server}")), "{}", body(&ex.response));

    // Wrong password: the proxy refuses, and the error says so.
    std::env::set_var("BP_TEST_HTTP_PROXY_PW", "wrong");
    let e = client(&g).send(&req, &target).await.unwrap_err();
    assert!(e.to_string().contains("credentials were refused"), "{e}");
}

#[tokio::test]
async fn socks5_proxy_with_username_and_password() {
    let server = echo_server().await;
    let (proxy, seen) = socks_proxy(Some(("bob", "pw"))).await;
    std::env::set_var("BP_TEST_SOCKS_PW", "pw");
    let g = Guard::from_specs(vec![spec(&["127.0.0.1"])]).unwrap();
    let rule = upstream("127.0.0.1", &format!("socks5://127.0.0.1:{proxy}"), Some("bob"), Some("BP_TEST_SOCKS_PW"));
    g.net.set(ConnectionSettings { upstream: vec![rule], ..Default::default() }.compile(vec![]).unwrap());
    let (req, target) = get(&format!("http://127.0.0.1:{server}/"));
    let ex = client(&g).send(&req, &target).await.unwrap();
    assert!(ex.response.starts_with(b"HTTP/1.1 200"));
    assert_eq!(*seen.lock().unwrap(), vec![format!("127.0.0.1:{server}")]);
    // Without credentials the proxy refuses.
    let rule = upstream("127.0.0.1", &format!("socks5://127.0.0.1:{proxy}"), None, None);
    g.net.set(ConnectionSettings { upstream: vec![rule], ..Default::default() }.compile(vec![]).unwrap());
    let e = client(&g).send(&req, &target).await.unwrap_err();
    assert!(e.to_string().contains("requires authentication"), "{e}");
}

#[tokio::test]
async fn new_settings_do_not_reuse_connections_opened_with_old_ones() {
    let server = echo_server().await;
    let (proxy, seen) = socks_proxy(None).await;
    let g = Guard::from_specs(vec![spec(&["127.0.0.1"])]).unwrap();
    let c = client(&g);
    let (req, target) = get(&format!("http://127.0.0.1:{server}/"));
    c.send(&req, &target).await.unwrap();
    let rule = upstream("*", &format!("socks5://127.0.0.1:{proxy}"), None, None);
    g.net.set(ConnectionSettings { upstream: vec![rule], ..Default::default() }.compile(vec![]).unwrap());
    c.send(&req, &target).await.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1, "the pooled direct connection was not reused");
}

#[tokio::test]
async fn a_connection_in_flight_when_settings_change_is_not_pooled() {
    let server = echo_server().await;
    let g = Guard::from_specs(vec![spec(&["127.0.0.1"])]).unwrap();
    let c = client(&g);
    let target = Target { scheme: "http".into(), host: "127.0.0.1".into(), port: server };
    let conn = c.checkout(&target, std::time::Duration::from_secs(30)).await.unwrap();
    // The settings change while it is out (a running proxy reloading them).
    g.net.set(ConnectionSettings::default().compile(vec![]).unwrap());
    c.checkin(&target, conn);
    let req = RawRequest::from_bytes(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec());
    c.send(&req, &target).await.unwrap();
    assert_eq!(c.connections_opened(), 2, "the old connection was not reused");
    c.send(&req, &target).await.unwrap();
    assert_eq!(c.connections_opened(), 2, "connections of the current settings still are");
}

#[tokio::test]
async fn proxies_off_this_machine_need_every_scope_to_list_them() {
    let g = Guard::from_specs(vec![spec(&["127.0.0.1", "192.0.2.0/24"])]).unwrap();
    // In the target scope is not enough: a proxy can read what goes through it.
    let e = g.resolve_proxy("192.0.2.10", 3128).await.unwrap_err();
    assert!(matches!(e, Error::OutOfScope(_)) && e.to_string().contains("engagement start --proxy"), "{e}");
    assert!(g.resolve_proxy("127.0.0.1", 3128).await.is_ok());
    assert!(g.resolve_proxy("localhost", 3128).await.is_ok());
    // An unlisted name is refused before DNS (which would carry the name out).
    let e = g.resolve_proxy("exfil.invalid", 3128).await.unwrap_err();
    assert!(e.to_string().contains("not allowed"), "{e}");
    assert!(g.resolve_proxy("::1", 3128).await.is_ok());
    let listed = Guard::from_specs_with_proxies(vec![
        (spec(&["127.0.0.1"]), vec!["192.0.2.10:3128".into()]),
        (spec(&["127.0.0.1"]), vec!["192.0.2.0/24".into()]),
    ])
    .unwrap();
    assert!(listed.resolve_proxy("192.0.2.10", 3128).await.is_ok());
    assert!(listed.resolve_proxy("192.0.2.10", 8080).await.is_err());
    // One scope not listing it is enough to refuse.
    let partly = Guard::from_specs_with_proxies(vec![
        (spec(&["127.0.0.1"]), vec!["192.0.2.10".into()]),
        (spec(&["127.0.0.1"]), vec![]),
    ])
    .unwrap();
    assert!(partly.resolve_proxy("192.0.2.10", 3128).await.is_err());
    // A refused proxy means no connection, not a direct one.
    let rule = upstream("*", "http://192.0.2.10:3128", None, None);
    g.net.set(ConnectionSettings { upstream: vec![rule], ..Default::default() }.compile(vec![]).unwrap());
    let (req, target) = get("http://127.0.0.1:9/");
    assert!(matches!(client(&g).send(&req, &target).await, Err(Error::OutOfScope(_))));
}

#[tokio::test]
async fn host_overrides_are_checked_like_dns_answers() {
    let server = echo_server().await;
    let overrides = |ip: &str| {
        ConnectionSettings {
            hosts: vec![
                HostOverride { host: "app.test".into(), ip: ip.parse().unwrap() },
                HostOverride { host: "x.wild.test".into(), ip: "10.1.2.3".parse().unwrap() },
            ],
            ..Default::default()
        }
        .compile(vec![])
        .unwrap()
    };
    // The name is in scope, but the overridden address (loopback) isn't.
    let names = Guard::from_specs(vec![spec(&["app.test", "*.wild.test"])]).unwrap();
    names.net.set(overrides("127.0.0.1"));
    let e = names.resolve("app.test", server).await.unwrap_err();
    assert!(e.to_string().contains("internal address 127.0.0.1"), "{e}");
    // A wildcard can't reach a private address through an override either.
    assert!(names.resolve("x.wild.test", 80).await.is_err());
    // Public address, exact name: allowed, without DNS.
    names.net.set(overrides("93.184.216.34"));
    assert_eq!(names.resolve("APP.test.", 443).await.unwrap(), vec!["93.184.216.34:443".parse().unwrap()]);
    // Listed by address: the request goes there with Host and SNI still the name.
    let g = Guard::from_specs(vec![spec(&["app.test", "127.0.0.1"])]).unwrap();
    g.net.set(overrides("127.0.0.1"));
    let (req, target) = get(&format!("http://app.test:{server}/"));
    let ex = client(&g).send(&req, &target).await.unwrap();
    assert!(body(&ex.response).contains(&format!("Host: app.test:{server}")));
}

/// A CA, a server certificate for localhost, and a client certificate, as files.
struct Pki {
    server: Arc<rustls::ServerConfig>,
    cert: PathBuf,
    key: PathBuf,
    p12: PathBuf,
}

fn pki(dir: &Path, h2: bool) -> Pki {
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    std::fs::create_dir_all(dir).unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let server_cert =
        CertificateParams::new(vec!["localhost".into()]).unwrap().signed_by(&server_key, &issuer).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec!["client.test".into()]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap();
    let mut server = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .unwrap();
    server.alpn_protocols = if h2 { vec![b"h2".to_vec()] } else { vec![b"http/1.1".to_vec()] };

    let cert = dir.join("client.pem");
    let key = dir.join("client.key");
    std::fs::write(&cert, client_cert.pem()).unwrap();
    std::fs::write(&key, client_key.serialize_pem()).unwrap();
    let mut store = p12_keystore::KeyStore::new();
    let chain = p12_keystore::PrivateKeyChain::new(
        b"1".to_vec(),
        p12_keystore::PrivateKey::from_der(&client_key.serialize_der()).unwrap(),
        [p12_keystore::Certificate::from_der(CertificateDer::from(client_cert.der().to_vec()).as_ref()).unwrap()],
    );
    store.add_entry("client", p12_keystore::KeyStoreEntry::PrivateKeyChain(chain));
    let p12 = dir.join("client.p12");
    std::fs::write(&p12, store.writer("p12-pass").write().unwrap()).unwrap();
    Pki { server: Arc::new(server), cert, key, p12 }
}

/// A TLS server that requires a client certificate; with `h2` it speaks HTTP/2.
async fn mtls_server(config: Arc<rustls::ServerConfig>, h2: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                if h2 {
                    let mut conn = ::h2::server::handshake(tls).await.unwrap();
                    while let Some(Ok((_, mut respond))) = conn.accept().await {
                        let resp = http::Response::builder().status(200).body(()).unwrap();
                        let mut send = respond.send_response(resp, false).unwrap();
                        send.send_data(bytes::Bytes::from_static(b"mutual"), true).unwrap();
                    }
                    return;
                }
                let mut reader = WireReader::new();
                while let Ok(Some(_)) = reader.read_request(&mut tls).await {
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nmutual").await;
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn client_certificates_for_mutual_tls_on_http1_and_http2() {
    let dir = std::env::temp_dir().join(format!("bp-mtls-{}", std::process::id()));
    std::env::set_var("BP_TEST_P12_PW", "p12-pass");
    for h2 in [false, true] {
        let pki = pki(&dir.join(if h2 { "h2" } else { "h1" }), h2);
        let port = mtls_server(pki.server.clone(), h2).await;
        let g = Guard::from_specs(vec![spec(&["localhost"])]).unwrap();
        let c = Client::new(SendOptions { guard: Some(g.clone()), http2: h2, ..Default::default() });
        let (req, target) = get(&format!("https://localhost:{port}/"));
        // No certificate: the server ends the handshake.
        assert!(c.send(&req, &target).await.is_err(), "h2={h2}");
        let pem = ClientCert {
            host: "localhost".into(),
            cert: Some(pki.cert.clone()),
            key: Some(pki.key.clone()),
            ..Default::default()
        };
        let p12 = ClientCert {
            host: "*".into(),
            pkcs12: Some(pki.p12.clone()),
            password_env: Some("BP_TEST_P12_PW".into()),
            ..Default::default()
        };
        for cert in [pem, p12] {
            let s = ConnectionSettings { client_certs: vec![cert.clone()], ..Default::default() };
            s.validate().unwrap();
            g.net.set(s.compile(vec![]).unwrap());
            let ex = c.send(&req, &target).await.unwrap_or_else(|e| panic!("h2={h2} {cert:?}: {e}"));
            assert!(ex.response.ends_with(b"mutual"), "h2={h2}");
        }
        // A certificate for other hosts isn't offered.
        let other = ClientCert {
            host: "other.test".into(),
            cert: Some(pki.cert.clone()),
            key: Some(pki.key.clone()),
            ..Default::default()
        };
        g.net.set(ConnectionSettings { client_certs: vec![other], ..Default::default() }.compile(vec![]).unwrap());
        assert!(c.send(&req, &target).await.is_err());
    }
    // A wrong password or missing file fails validation, and connections to its hosts.
    let bad = ClientCert { host: "*".into(), pkcs12: Some(dir.join("h1/client.p12")), ..Default::default() };
    let s = ConnectionSettings { client_certs: vec![bad], ..Default::default() };
    assert!(s.validate().unwrap_err().to_string().contains("wrong password"));
    let g = Guard::from_specs(vec![spec(&["localhost"])]).unwrap();
    g.net.set(s.compile(vec![]).unwrap());
    let (req, target) = get("https://localhost:9/");
    let e = client(&g).send(&req, &target).await.unwrap_err();
    assert!(e.to_string().contains("client certificate for localhost"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn platform_cred(scheme: PlatformScheme, user: &str, password: &str) -> PlatformCred {
    let p = crate::auth::AuthProfile {
        name: "corp".into(),
        username: Some(user.into()),
        password: Some(crate::auth::Secret::Literal(password.into())),
        platform: Some(PlatformAuth { scheme, hosts: vec!["127.0.0.1".into()], domain: None }),
        ..Default::default()
    };
    PlatformCred::from_profile(&p).unwrap().unwrap()
}

#[derive(Default)]
struct AuthLog {
    /// Requests the server read, with the Authorization header each had.
    requests: Vec<Option<String>>,
    connections: usize,
}

fn authorization(req: &[u8]) -> Option<String> {
    let head = RawRequest::from_bytes(crate::http::request::split_head_body(req).0.to_vec()).head().ok()?;
    head.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.clone())
}

const UNAUTHORIZED: &str = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n";

/// A server that wants Basic `alice:pw`.
async fn basic_server() -> (u16, Arc<Mutex<AuthLog>>) {
    serve_auth(|auth, _| {
        let ok = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("alice:pw"));
        if auth.as_deref() == Some(&ok) {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nin".to_string()
        } else {
            format!("{UNAUTHORIZED}WWW-Authenticate: Basic realm=\"r\"\r\n\r\n")
        }
    })
    .await
}

/// Runs `answer(authorization, connection state)` for each request on each connection.
async fn serve_auth<F>(answer: F) -> (u16, Arc<Mutex<AuthLog>>)
where
    F: Fn(Option<String>, &mut Vec<u8>) -> String + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Arc<Mutex<AuthLog>> = Arc::default();
    let (l, answer) = (log.clone(), Arc::new(answer));
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            l.lock().unwrap().connections += 1;
            let (l, answer) = (l.clone(), answer.clone());
            tokio::spawn(async move {
                let mut reader = WireReader::new();
                let mut state = Vec::new();
                while let Ok(Some(req)) = reader.read_request(&mut s).await {
                    let auth = authorization(&req);
                    l.lock().unwrap().requests.push(auth.clone());
                    if s.write_all(answer(auth, &mut state).as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, log)
}

fn platform_guard(cred: PlatformCred) -> Arc<Guard> {
    let g = Guard::from_specs(vec![spec(&["127.0.0.1"])]).unwrap();
    g.net.set(ConnectionSettings::default().compile(vec![cred]).unwrap());
    g
}

#[tokio::test]
async fn basic_answers_the_challenge_then_goes_first() {
    let (port, log) = basic_server().await;
    let c = client(&platform_guard(platform_cred(PlatformScheme::Basic, "alice", "pw")));
    let (req, target) = get(&format!("http://127.0.0.1:{port}/"));
    let ex = c.send(&req, &target).await.unwrap();
    assert!(ex.response.ends_with(b"in"));
    // History gets the request as given: no credentials.
    assert!(authorization(&ex.request).is_none());
    c.send(&req, &target).await.unwrap();
    {
        let log = log.lock().unwrap();
        assert_eq!(log.requests.len(), 3, "the second request carried Basic from the start");
        assert!(log.requests[0].is_none() && log.requests[2].is_some());
    }
    // A request with its own Authorization header is left alone.
    let (own, _) = RawRequest::build(
        "GET",
        &format!("http://127.0.0.1:{port}/"),
        &[("Authorization".into(), "Basic eA==".into())],
        b"",
    )
    .unwrap();
    assert!(c.send(&own, &target).await.unwrap().response.starts_with(b"HTTP/1.1 401"));
}

#[tokio::test]
async fn digest_answers_with_a_valid_response() {
    let (port, log) = serve_auth(|auth, _| {
        let challenge = "Digest realm=\"lab\", qop=\"auth\", nonce=\"abc123\", opaque=\"xyz\", algorithm=SHA-256";
        let Some(a) = auth.filter(|a| a.starts_with("Digest ")) else {
            return format!("{UNAUTHORIZED}WWW-Authenticate: {challenge}\r\n\r\n");
        };
        // Check the response the way a server does.
        let mut ch = Vec::new();
        platform::parse_challenges(&a, &mut ch);
        let p = &ch[0].params;
        let h = |s: String| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(s.as_bytes()));
        let ha1 = h(format!("{}:lab:pw", p["username"]));
        let ha2 = h(format!("GET:{}", p["uri"]));
        let want = h(format!("{ha1}:abc123:{}:{}:auth:{ha2}", p["nc"], p["cnonce"]));
        if p["response"] == want && p["opaque"] == "xyz" && p["username"] == "alice" {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nin".into()
        } else {
            format!("{UNAUTHORIZED}\r\n")
        }
    })
    .await;
    let c = client(&platform_guard(platform_cred(PlatformScheme::Digest, "alice", "pw")));
    let (req, target) = get(&format!("http://127.0.0.1:{port}/a?b=1"));
    assert!(c.send(&req, &target).await.unwrap().response.ends_with(b"in"));
    // The next request goes with the next nonce count, without a 401 first.
    assert!(c.send(&req, &target).await.unwrap().response.ends_with(b"in"));
    let log = log.lock().unwrap();
    assert_eq!(log.requests.len(), 3);
    assert!(log.requests[2].as_deref().unwrap().contains("nc=00000002"));
}

#[tokio::test]
async fn ntlm_handshake_on_one_connection() {
    use platform::ntlm;
    let server_challenge = [7u8; 8];
    let info = hex::decode("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000").unwrap();
    let challenge_msg = {
        let mut m = b"NTLMSSP\0".to_vec();
        m.extend_from_slice(&2u32.to_le_bytes());
        m.extend_from_slice(&[0, 0, 0, 0, 56, 0, 0, 0]); // empty target name
        m.extend_from_slice(&0xa288_8205u32.to_le_bytes());
        m.extend_from_slice(&server_challenge);
        m.extend_from_slice(&[0u8; 8]);
        m.extend_from_slice(&(info.len() as u16).to_le_bytes());
        m.extend_from_slice(&(info.len() as u16).to_le_bytes());
        m.extend_from_slice(&56u32.to_le_bytes());
        m.extend_from_slice(&[0u8; 8]); // version
        m.extend_from_slice(&info);
        m
    };
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let type2 = b64(&challenge_msg);
    let (port, log) = serve_auth(move |auth, state| {
        // state: b"ok" once this connection has authenticated.
        if state.as_slice() == b"ok" {
            return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nin".into();
        }
        let msg = auth
            .as_deref()
            .and_then(|a| a.strip_prefix("NTLM "))
            .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok());
        match msg {
            None => format!("{UNAUTHORIZED}WWW-Authenticate: Negotiate\r\nWWW-Authenticate: NTLM\r\n\r\n"),
            Some(m) if m[8] == 1 => format!("{UNAUTHORIZED}WWW-Authenticate: NTLM {type2}\r\n\r\n"),
            Some(m) => {
                // AUTHENTICATE: check the NTLMv2 proof for CORP\alice / pw.
                let field = |at: usize| {
                    let len = u16::from_le_bytes([m[at], m[at + 1]]) as usize;
                    let off = u32::from_le_bytes(m[at + 4..at + 8].try_into().unwrap()) as usize;
                    m[off..off + len].to_vec()
                };
                let nt = field(20);
                let user: String = char::decode_utf16(field(36).chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])))
                    .map(|c| c.unwrap())
                    .collect();
                let key = ntlm::ntowf_v2("pw", &user, "CORP");
                let proof = ntlm::hmac_md5(&key, &[&server_challenge, &nt[16..]]);
                if proof[..] == nt[..16] && user == "alice" {
                    *state = b"ok".to_vec();
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nin".into()
                } else {
                    format!("{UNAUTHORIZED}\r\n")
                }
            }
        }
    })
    .await;
    let c = client(&platform_guard(platform_cred(PlatformScheme::Ntlm, "CORP\\alice", "pw")));
    let keep = [("Connection".to_string(), "keep-alive".to_string())];
    let (req, target) = RawRequest::build("GET", &format!("http://127.0.0.1:{port}/"), &keep, b"").unwrap();
    let ex = c.send(&req, &target).await.unwrap();
    assert!(ex.response.ends_with(b"in"), "{}", String::from_utf8_lossy(&ex.response));
    assert!(authorization(&ex.request).is_none());
    // The authenticated connection is pooled: the next request needs no handshake.
    c.send(&req, &target).await.unwrap();
    {
        let log = log.lock().unwrap();
        assert_eq!((log.requests.len(), log.connections), (4, 1));
    }
    // `Connection: close` on the request: the handshake still happens on one connection.
    let (close, _) = get(&format!("http://127.0.0.1:{port}/"));
    assert!(c.send(&close, &target).await.unwrap().response.ends_with(b"in"));
}
