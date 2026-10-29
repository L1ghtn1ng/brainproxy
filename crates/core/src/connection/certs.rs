//! Client certificates for mutual TLS: a PEM certificate chain with its PEM key,
//! or a PKCS#12 file whose password comes from an environment variable.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::connection::ClientCert;
use crate::error::{Error, Result};

/// A loaded certificate chain and key, or why it couldn't be loaded.
pub struct ClientIdentity {
    pub chain: Vec<CertificateDer<'static>>,
    key: Option<PrivateKeyDer<'static>>,
    /// Set when the files couldn't be read; connections that need it fail with this.
    pub error: Option<String>,
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity").field("chain", &self.chain.len()).field("error", &self.error).finish()
    }
}

impl ClientIdentity {
    /// Loads the files. Errors in the entry itself (no files, both kinds) are
    /// errors; problems reading the files are kept in `error`.
    pub fn load(c: &ClientCert) -> Result<Self> {
        let loaded = match (&c.cert, &c.key, &c.pkcs12) {
            (Some(cert), Some(key), None) => load_pem(cert, key),
            (None, None, Some(p12)) => load_pkcs12(p12, c.password_env.as_deref()),
            (Some(_), None, None) => {
                return Err(Error::InvalidInput(format!("client certificate for {}: --cert needs --key", c.host)))
            }
            _ => {
                return Err(Error::InvalidInput(format!(
                    "client certificate for {}: give --cert and --key (PEM), or --pkcs12",
                    c.host
                )))
            }
        };
        Ok(match loaded {
            Ok((chain, key)) => Self { chain, key: Some(key), error: None },
            Err(e) => Self { chain: vec![], key: None, error: Some(e) },
        })
    }

    /// A copy of the key for a TLS client configuration.
    pub fn key(&self) -> Result<PrivateKeyDer<'static>> {
        match (&self.key, &self.error) {
            (Some(k), _) => Ok(k.clone_key()),
            (None, e) => Err(Error::Tls(e.clone().unwrap_or_else(|| "no client key".into()))),
        }
    }
}

type Loaded = std::result::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String>;

fn load_pem(cert: &std::path::Path, key: &std::path::Path) -> Loaded {
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|i| i.collect::<std::result::Result<Vec<_>, _>>())
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{}: no PEM certificate", cert.display()));
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    check_key(&key)?;
    Ok((chain, key))
}

fn load_pkcs12(path: &std::path::Path, password_env: Option<&str>) -> Loaded {
    let password = match password_env {
        Some(var) => std::env::var(var).map_err(|_| format!("PKCS#12 password variable {var} is not set"))?,
        None => String::new(),
    };
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let store = p12_keystore::KeyStore::from_pkcs12(&data, &password, p12_keystore::Pkcs12ImportPolicy::Relaxed)
        .map_err(|e| format!("{}: {e} (wrong password?)", path.display()))?;
    let (_, chain) =
        store.private_key_chain().ok_or_else(|| format!("{}: no private key in the file", path.display()))?;
    let certs: Vec<CertificateDer<'static>> =
        chain.certs().iter().map(|c| CertificateDer::from(c.as_der().to_vec())).collect();
    if certs.is_empty() {
        return Err(format!("{}: no certificate for the private key", path.display()));
    }
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chain.key().as_der().to_vec()));
    check_key(&key)?;
    Ok((certs, key))
}

fn check_key(key: &PrivateKeyDer<'_>) -> std::result::Result<(), String> {
    rustls::crypto::ring::sign::any_supported_type(key).map(|_| ()).map_err(|e| format!("unsupported private key: {e}"))
}
