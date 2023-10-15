//! Types for the public releases information.
use crate::{Arch, Artifact, Channel, Platform};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Release information.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseInfo {
    /// GUI release information.
    pub gui: GuiReleaseInfo,
}

/// Release information for the GUI.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GuiReleaseInfo {
    /// Release channels for the GUI.
    #[serde(flatten)]
    pub channels: HashMap<Channel, PlatformRelease>,
}

impl GuiReleaseInfo {
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

    static JSON: &str = r#"
{
  "gui": {
    "beta": {
      "meta": {
        "version": "1.0.0-beta+87",
        "notes": {
          "text": "https://releases.saveoursecrets.com/beta/gui/1.0.0-beta+87/release-notes.txt",
          "markdown": "https://releases.saveoursecrets.com/beta/gui/1.0.0-beta+87/release-notes.md",
          "html": "https://releases.saveoursecrets.com/beta/gui/1.0.0-beta+87/release-notes.html"
        }
      },
      "platforms": {
        "macos": [
          {
            "platform": "macos",
            "arch": "universal",
            "name": "saveoursecrets.pkg",
            "version": "1.0.0-beta+87",
            "sha256": "4ba319beb284bc557f9b51def8d1dc2b15dfdf6273a8bd88a2153b8c1be1b5e6",
            "timestamp": "2023-10-09 10:45:31.958386 +00:00:00",
            "commit": "f75273c6f6d371000247f8492234e9318132c3da",
            "size": 39424923,
            "artifact": "https://releases.saveoursecrets.com/beta/gui/1.0.0-beta+87/macos/universal/saveoursecrets.pkg"
          }
        ],
        "debian": [
          {
            "platform": "debian",
            "arch": "x86_64",
            "name": "saveoursecrets.deb",
            "version": "1.0.0-beta+87",
            "sha256": "e586f7a52a46980a9d3050eee492fe0f33f5a26012fa1ab4f956d4f2c648076f",
            "timestamp": "2023-10-09 10:44:14.403563787 +00:00:00",
            "commit": "f75273c6f6d371000247f8492234e9318132c3da",
            "size": 17865892,
            "artifact": "https://releases.saveoursecrets.com/beta/gui/1.0.0-beta+87/debian/x86_64/saveoursecrets.deb"
          }
        ],
        "windows": [
          {
            "platform": "windows",
            "arch": "x86_64",
            "name": "saveoursecrets.msix",
            "version": "1.0.0-beta+87",
            "sha256": "02419bfcd8af8d712ecb979aba0ffc60c52be2d8fa74785a79fef9f0f5a680d3",
            "timestamp": "2023-10-09 10:56:26.3850014 +00:00:00",
            "commit": "f75273c6f6d371000247f8492234e9318132c3da",
            "size": 22763771,
            "artifact": "https://releases.saveoursecrets.com/beta/gui/1.0.0-beta+87/windows/x86_64/saveoursecrets.msix"
          }
        ],
        "android": [
          {
            "platform": "android",
            "arch": "universal",
            "name": "saveoursecrets.apk",
            "version": "1.0.0-beta+87",
            "sha256": "ee620681fd4e6a0f45f8385b9e17a8030e4efa27c8b7b0f573721318a25c462c",
            "timestamp": "2023-10-09 10:41:41.668717765 +00:00:00",
            "commit": "f75273c6f6d371000247f8492234e9318132c3da",
            "size": 76830841,
            "artifact": "https://releases.saveoursecrets.com/beta/gui/1.0.0-beta+87/android/universal/saveoursecrets.apk",
            "store": "https://play.google.com/store/apps/details?id=com.saveoursecrets"
          }
        ],
        "ios": [
          {
            "platform": "ios",
            "arch": "universal",
            "name": "saveoursecrets.ipa",
            "version": "1.0.0-beta+87",
            "sha256": "2854aa7deaed63db34722de998b79f44f97bc6ab2915e177cf78cb313ea14302",
            "timestamp": "2023-10-09 10:57:19.820767 +00:00:00",
            "commit": "f75273c6f6d371000247f8492234e9318132c3da",
            "size": 116151448,
            "artifact": "https://releases.saveoursecrets.com/beta/gui/1.0.0-beta+87/ios/universal/saveoursecrets.ipa",
            "store": "https://appstore.com/saveoursecrets"
          }
        ]
      }
    }
  }
}
"#;

    #[test]
    fn test_serde() -> Result<()> {
        let mut info = ReleaseInfo {
            gui: Default::default(),
        };

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
        Ok(())
    }
}
