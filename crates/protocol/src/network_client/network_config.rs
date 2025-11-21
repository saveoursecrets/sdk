use crate::Result;
use parking_lot::Mutex;
use reqwest::Certificate;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::{collections::HashMap, path::Path};

/// Manages client network configuration such as TLS root certificates and
/// explicit DNS to socket address mappings.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    resolve_addrs: HashMap<String, SocketAddr>,
    #[serde(skip)]
    certificates: HashMap<String, Certificate>,
}

static NETWORK_CONFIG: OnceLock<Mutex<NetworkConfig>> = OnceLock::new();

impl NetworkConfig {
    /// Load root certificates from a directory into memory.
    ///
    /// Intended to be called as early as possible when the application
    /// starts so root certificates are available to the HTTP client.
    pub fn load_root_certificates<P: AsRef<Path>>(
        certificates_path: P,
    ) -> Result<()> {
        let config =
            NETWORK_CONFIG.get_or_init(|| Mutex::new(Default::default()));

        let mut certs = HashMap::new();
        if certificates_path.as_ref().exists() {
            for entry in std::fs::read_dir(certificates_path)? {
                let path = entry?.path();
                if path.is_file() {
                    let content = std::fs::read_to_string(&path)?;
                    let cert = Certificate::from_pem(content.as_bytes())?;
                    let cert_id = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();

                    certs.insert(cert_id, cert);
                }
            }
        }

        let mut config = config.lock();
        config.certificates = certs;

        Ok(())
    }

    /// Get root certificates from memory.
    pub fn get_root_certificates() -> Vec<Certificate> {
        let config =
            NETWORK_CONFIG.get_or_init(|| Mutex::new(Default::default()));
        let config = config.lock();
        config.certificates.values().cloned().collect()
    }

    /// Import a PEM-encoded root certificate to the certificates directory and into memory.
    ///
    /// If a certificate already exists with the given file name it is overwritten on disc and
    /// in memory.
    pub fn import_root_certificate<P: AsRef<Path>>(
        certificates_path: P,
        source_pem: P,
    ) -> Result<()> {
        if !certificates_path.as_ref().exists() {
            std::fs::create_dir_all(certificates_path.as_ref())?;
        }

        let content = std::fs::read_to_string(&source_pem)?;
        let cert = Certificate::from_pem(content.as_bytes())?;

        let dest = certificates_path
            .as_ref()
            .join(source_pem.as_ref().file_name().unwrap_or_default());
        std::fs::write(dest, content.as_bytes())?;

        let cert_id = source_pem
            .as_ref()
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        let config =
            NETWORK_CONFIG.get_or_init(|| Mutex::new(Default::default()));
        let mut config = config.lock();
        config.certificates.insert(cert_id, cert);
        Ok(())
    }

    /// Delete a PEM-encoded root certificate from the certificates directory and memory.
    pub fn delete_root_certificate<P: AsRef<Path>>(
        certificates_path: P,
        cert_id: &str,
    ) -> Result<()> {
        let dest = certificates_path.as_ref().join(cert_id);
        if dest.exists() {
            std::fs::remove_file(dest)?;
        }

        let config =
            NETWORK_CONFIG.get_or_init(|| Mutex::new(Default::default()));
        let mut config = config.lock();
        config.certificates.remove(cert_id);
        Ok(())
    }
}
