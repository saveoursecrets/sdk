//! Types for release artifact meta data.
use crate::Error;
use serde::{
    de::{self, Deserializer, Visitor},
    Deserialize, Serialize, Serializer,
};
use std::{fmt, str::FromStr};
use time::OffsetDateTime;
use url::Url;

/// File stem for release artifacts.
pub const FILE_STEM: &str = "saveoursecrets";

/// Extension appended for signature files.
pub const SIG_EXT: &str = "sig.txt";

/// Extension appended for SHA256 checksum files.
pub const SHA_EXT: &str = "sha256.txt";

/// Artifact meta data represents a file.
#[derive(Debug, Serialize, Deserialize)]
pub struct Artifact {
    /// Platform name.
    pub platform: Platform,
    /// Processor architecture.
    pub arch: Arch,
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
    /// URL to a release artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<Url>,
    /// URL to the app on the Play or App store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<Url>,
}

/// Distribution channel.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
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

/// Processor architecture.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// Universal binary (MacOS, iOS and Android).
    Universal,
    /// Intel 64 bit chips.
    X86_64,
    /// 64 bit ARM chips.
    Aarch64,
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Universal => "universal",
                Self::X86_64 => "x86_64",
                Self::Aarch64 => "aarch64",
            }
        )
    }
}

impl FromStr for Arch {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "universal" => Self::Universal,
            "x86_64" => Self::X86_64,
            "aarch64" => Self::Aarch64,
            _ => return Err(Error::UnknownArch(s.to_owned())),
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
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Platform {
    /// Linux.
    Linux(Distro),
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

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Linux(distro) => match distro {
                    Distro::Unknown => "linux",
                    Distro::Debian => "debian",
                    Distro::RedHat => "redhat",
                    Distro::Flatpak => "flatpak",
                },
                Self::Windows => "windows",
                Self::MacOS => "macos",
                Self::iOS => "ios",
                Self::Android => "android",
            }
        )
    }
}

impl FromStr for Platform {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "linux" => Self::Linux(Distro::Unknown),
            "debian" => Self::Linux(Distro::Debian),
            "redhat" => Self::Linux(Distro::RedHat),
            "flatpak" => Self::Linux(Distro::Flatpak),
            "windows" => Self::Windows,
            "macos" => Self::MacOS,
            "ios" => Self::iOS,
            "android" => Self::Android,
            _ => return Err(Error::UnknownPlatform(s.to_owned())),
        })
    }
}

impl Serialize for Platform {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Platform {
    fn deserialize<D>(deserializer: D) -> Result<Platform, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(PlatformVisitor)
    }
}

struct PlatformVisitor;

impl<'de> Visitor<'de> for PlatformVisitor {
    type Value = Platform;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a valid platform identifier")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let platform: Platform = value.parse().map_err(E::custom)?;
        Ok(platform)
    }
}

/// Distribution for the Linux platform.
#[derive(
    Default, Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Distro {
    /// Unknown distro.
    #[default]
    Unknown,
    /// Debian Linux.
    Debian,
    /// RedHat Linux (Fedora, CentOS etc).
    RedHat,
    /// Flatpak bundle or repository.
    Flatpak,
}

impl fmt::Display for Distro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Unknown => "linux",
                Self::Debian => "debian",
                Self::RedHat => "redhat",
                Self::Flatpak => "flatpak",
            }
        )
    }
}

impl FromStr for Distro {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "linux" => Self::Unknown,
            "debian" => Self::Debian,
            "redhat" => Self::RedHat,
            "flatpak" => Self::Flatpak,
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
