//! Types for release artifact meta data.
//!
//! Provides serde support and string parsing for types 
//! that can be supplied as command line arguments.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::{fmt, str::FromStr};
use thiserror::Error;
use time::OffsetDateTime;
use serde::{Serialize, Deserialize};

/// Error thrown by the artifact library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error when a distro is invalid.
    #[error("unknown distribution platform {0}")]
    UnknownDistro(String),

    /// Error when a distribution collection is invalid.
    ///
    /// Supported values are currently `gui` and `cli`.
    #[error("unknown collection {0}")]
    UnknownCollection(String),
    
    /// Error when a distribution channel is invalid.
    #[error("unknown distribution channel {0}")]
    UnknownChannel(String),

    /// Error when a platform variant is invalid.
    #[error("unknown platform variant {0}")]
    UnknownVariant(String),
}

/// Artifact meta data represents a file.
#[derive(Debug, Serialize, Deserialize)]
pub struct Artifact {
    /// Distro channel name.
    pub distro: Distro,
    /// Processor architecture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// File name.
    pub name: String,
    /// Build version.
    pub version: semver::Version,
    /// Hash digest.
    #[serde(with = "hex::serde")]
    pub sha256: Vec<u8>,
    /// Date and time.
    pub timestamp: OffsetDateTime,
    /// Commit hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// File size of the artifact.
    pub size: u64,
}

/// Distribution channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// Beta channel.
    Beta,
    /// Stable channel.
    Stable,
    /// Canary channel.
    Canary,
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Stable => "stable",
                Self::Beta => "beta",
                Self::Canary => "canary",
            }
        )
    }
}

impl FromStr for Channel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "stable" => Self::Stable,
            "beta" => Self::Beta,
            _ => return Err(Error::UnknownChannel(s.to_owned())),
        })
    }
}

/// Collection of artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Collection {
    /// Command line tools.
    Cli,
    /// Graphical user interfaces.
    Gui,
}

impl fmt::Display for Collection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Cli => "cli",
                Self::Gui => "gui",
            }
        )
    }
}

impl FromStr for Collection {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "cli" => Self::Cli,
            "gui" => Self::Gui,
            _ => return Err(Error::UnknownCollection(s.to_owned())),
        })
    }
}

/// Distribution platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Distro {
    /// Linux.
    Linux,
    /// Debian Linux.
    Debian,
    /// RedHat Linux (Fedora, CentOS etc).
    RedHat,
    /// Windows.
    Windows,
    /// MacOS.
    MacOS,
    /// iOS.
    #[allow(non_camel_case_types)]
    iOS,
    /// Android.
    Android,
}

impl fmt::Display for Distro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Linux => "linux",
                Self::Debian => "debian",
                Self::RedHat => "redhat",
                Self::Windows => "windows",
                Self::MacOS => "macos",
                Self::iOS => "ios",
                Self::Android => "android",
            }
        )
    }
}

impl FromStr for Distro {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "linux" => Self::Linux,
            "debian" => Self::Debian,
            "redhat" => Self::RedHat,
            "windows" => Self::Windows,
            "macos" => Self::MacOS,
            "ios" => Self::iOS,
            "android" => Self::Android,
            _ => return Err(Error::UnknownDistro(s.to_owned())),
        })
    }
}

/// Platform variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Variant {
    /// No variant.
    None,
    /// MUSL.
    Musl,
}

impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::None => "none",
                Self::Musl => "musl",
            }
        )
    }
}

impl FromStr for Variant {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "none" => Self::None,
            "musl" => Self::Musl,
            _ => return Err(Error::UnknownVariant(s.to_owned())),
        })
    }
}
