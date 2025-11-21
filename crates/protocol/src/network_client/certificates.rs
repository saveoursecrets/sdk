use crate::Result;
use parking_lot::Mutex;
use reqwest::Certificate;
use std::sync::OnceLock;
use std::{collections::HashMap, path::Path};

static CERTIFICATES: OnceLock<Mutex<HashMap<String, Certificate>>> =
    OnceLock::new();

/// Manage root TLS certificates.
pub struct RootCertificate;

impl RootCertificate {
    /// Load root certificates from a directory into memory.
    ///
    /// Intended to be called as early as possible when the application
    /// starts so root certificates are available to the HTTP client.
    pub fn load_root_certificates<P: AsRef<Path>>(
        certificates_path: P,
    ) -> Result<()> {
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
        CERTIFICATES.get_or_init(|| Mutex::new(certs));
        Ok(())
    }

    /// Get root certificates from memory.
    pub fn get_root_certificates() -> Vec<Certificate> {
        let certs = CERTIFICATES.get_or_init(|| Mutex::new(HashMap::new()));
        let certs = certs.lock();
        certs.values().cloned().collect()
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

        let certs = CERTIFICATES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut certs = certs.lock();
        certs.insert(cert_id, cert);
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

        let certs = CERTIFICATES.get_or_init(|| Mutex::new(HashMap::new()));
        let mut certs = certs.lock();
        certs.remove(cert_id);
        Ok(())
    }
}
