//! Types for the public releases information.
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use url::Url;
use crate::{Channel, Artifact, Distro};

/// Release information.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseInfo {
    /// GUI release information.
    pub gui: GuiReleaseInfo,
}

/// Release information for the GUI.
#[derive(Debug, Serialize, Deserialize)]
pub struct GuiReleaseInfo {
    /// Release channels for the GUI.
    #[serde(flatten)]
    pub channels: HashMap<Channel, ChannelRelease>,
}

/// Release information for a single channel.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChannelRelease {
    /// Release artifact for MacOS.
    pub macos: Artifact,
    /// Release artifacts for Linux.
    pub linux: LinuxRelease,
    /// Release artifact for Windows.
    pub windows: Artifact,
    /// Release artifact for Android.
    pub android: Artifact,
    /// Release information for iOS.
    pub ios: IosRelease,
}

impl ChannelRelease {
    /// Find an artifact by distro.
    pub fn find_by_distro(&self, distro: &Distro) -> Option<&Artifact> {
        match distro {
            Distro::MacOS => Some(&self.macos),
            Distro::Linux => Some(&self.linux.debian),
            Distro::Debian => Some(&self.linux.debian),
            Distro::Windows => Some(&self.windows),
            Distro::Android => Some(&self.android),
            _ => None,
        }
    }
}

/// Release information for the linux platform.
#[derive(Debug, Serialize, Deserialize)]
pub struct LinuxRelease {
    /// Release information for debian distros.
    pub debian: Artifact,
}

/// Release information for the iOS platform.
#[derive(Debug, Serialize, Deserialize)]
pub struct IosRelease {
    /// URL to the app store installer.
    pub store: Url,
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;

    static JSON:&str = r#"{
  "gui": {
    "beta": {
      "macos": {
        "distro": "macos",
        "name": "saveoursecrets.pkg",
        "version": "1.0.0-beta1+83",
        "sha256": "4276fff9125fd39ea1da6e5d97e06c6f840a5819dfd8a08af0a6519e3dd231f1",
        "timestamp": "2023-10-07 07:17:27.64777 +00:00:00",
        "commit": "cbae2ed875037917d74298e1e608baac984b5d95",
        "size": 38517226,
        "artifact": "https://releases.saveoursecrets.com/beta/gui/macos/1.0.0-beta1+83/saveoursecrets.pkg"
      },
      "linux": {
        "debian": {
          "distro": "debian",
          "arch": "x86_64",
          "name": "saveoursecrets.deb",
          "version": "1.0.0-beta1+83",
          "sha256": "4d56f4001fca4a490a5ebcce17d2ef1d1b76d0cccfa1797ad7853c944bbe0aa8",
          "timestamp": "2023-10-07 07:16:01.308760682 +00:00:00",
          "commit": "cbae2ed875037917d74298e1e608baac984b5d95",
          "size": 17398354,
          "artifact": "https://releases.saveoursecrets.com/beta/gui/debian/1.0.0-beta1+83/x86_64/saveoursecrets.deb"
        }
      },
      "windows": {
        "distro": "windows",
        "arch": "x86_64",
        "name": "saveoursecrets.msix",
        "version": "1.0.0-beta1+83",
        "sha256": "d443e491b92e191edf0d9b94b4fd9e6f1aa0d8f4464dd5e46248a1b34e083a2b",
        "timestamp": "2023-10-07 07:30:04.9398342 +00:00:00",
        "commit": "cbae2ed875037917d74298e1e608baac984b5d95",
        "size": 22370419,
        "artifact": "https://releases.saveoursecrets.com/beta/gui/windows/1.0.0-beta1+83/x86_64/saveoursecrets.msix"
      },
      "android": {
        "distro": "android",
        "name": "saveoursecrets.apk",
        "version": "1.0.0-beta1+83",
        "sha256": "8658a9783afb268d3acd0f9359d1d7e82276776f6e8ec7b7c6d7a778199a8bdb",
        "timestamp": "2023-10-07 07:15:10.658351133 +00:00:00",
        "commit": "cbae2ed875037917d74298e1e608baac984b5d95",
        "size": 73603193,
        "artifact": "https://releases.saveoursecrets.com/beta/gui/android/1.0.0-beta1+83/saveoursecrets.apk",
        "store": "https://play.google.com/store/apps/details?id=com.saveoursecrets"
      },
      "ios": {
        "store": "https://appstore.com/saveoursecrets"
      }
    }
  }
}"#;
    
    #[test]
    fn test_serde() -> Result<()> {
        let info: ReleaseInfo = serde_json::from_str(JSON)?;
        let name = &info.gui.channels.get(&Channel::Beta).unwrap().macos.name;
        assert_eq!("saveoursecrets.pkg", name);
        Ok(())
    }
}
