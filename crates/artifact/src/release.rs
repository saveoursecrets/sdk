//! Types for the public releases information.
use crate::{Arch, Artifact, Channel, Platform};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Release information.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ReleaseInfo {
    /// GUI release information.
    pub gui: ReleaseCollection,
    /// CLI release information.
    pub cli: ReleaseCollection,
}

/// Release information for a collection.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ReleaseCollection {
    /// Release channels for a collection.
    #[serde(flatten)]
    pub channels: HashMap<Channel, PlatformRelease>,
}

impl ReleaseCollection {
    /// Find an artifact by distro.
    pub fn find(
        &self,
        channel: &Channel,
        platform: &Platform,
        arch: &Arch,
    ) -> Option<&Artifact> {
        if let Some(channel) = self.channels.get(channel) {
            if let Some(releases) = channel.platforms.get(platform) {
                releases.iter().find(|r| &r.arch == arch)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get the meta data for a channel.
    pub fn meta(&self, channel: &Channel) -> Option<&ReleaseMeta> {
        if let Some(channel) = self.channels.get(channel) {
            Some(&channel.meta)
        } else {
            None
        }
    }
}

/// Release notes download information.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseNotes {
    /// The URL for text release notes.
    pub text: Url,
    /// The URL for markdown release notes.
    pub markdown: Url,
    /// The URL for html release notes.
    pub html: Url,
}

/// Meta data for a single release.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseMeta {
    /// The version for all the platforms.
    pub version: semver::Version,
    /// Release notes.
    pub notes: ReleaseNotes,
}

/// Release information for a platform.
#[derive(Debug, Serialize, Deserialize)]
pub struct PlatformRelease {
    /// Release meta data.
    pub meta: ReleaseMeta,
    /// Release channels for the GUI.
    pub platforms: HashMap<Platform, Vec<Artifact>>,
}

/// Release information for a platform.
#[derive(Debug, Serialize, Deserialize)]
pub struct Release {
    artifact: Artifact,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::*;
    use anyhow::Result;
    use time::OffsetDateTime;

    static JSON: &str = include_str!("releases.json");

    #[test]
    fn test_serde() -> Result<()> {
        let mut info: ReleaseInfo = Default::default();

        info.gui.channels.insert(
            Channel::Beta,
            PlatformRelease {
                meta: ReleaseMeta {
                    version: "1.0.0".parse()?,
                    notes: ReleaseNotes {
                        text: "https://example.com".parse()?,
                        markdown: "https://example.com".parse()?,
                        html: "https://example.com".parse()?,
                    },
                },
                platforms: Default::default(),
            },
        );

        info.gui
            .channels
            .get_mut(&Channel::Beta)
            .unwrap()
            .platforms
            .insert(
                Platform::Linux(Distro::Debian),
                vec![Artifact {
                    platform: Platform::Linux(Distro::Debian),
                    name: String::new(),
                    sha256: vec![],
                    arch: Arch::X86_64,
                    commit: None,
                    timestamp: OffsetDateTime::now_utc(),
                    version: "1.0.0".parse()?,
                    artifact: None,
                    size: 0,
                    store: None,
                }],
            );

        let json = serde_json::to_string_pretty(&info)?;
        serde_json::from_str::<ReleaseInfo>(&json)?;

        let info: ReleaseInfo = serde_json::from_str(JSON)?;
        let artifact = &info.gui.find(
            &Channel::Beta,
            &Platform::MacOS,
            &Arch::Universal,
        );
        assert!(artifact.is_some());

        let artifact =
            &info
                .cli
                .find(&Channel::Beta, &Platform::MacOS, &Arch::Aarch64);
        assert!(artifact.is_some());

        Ok(())
    }
}
