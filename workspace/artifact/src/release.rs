//! Types for the public releases information.
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::{Channel, Artifact, Platform, Arch};

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
    pub channels: HashMap<Channel, PlatformRelease>,
}

impl GuiReleaseInfo {
    /// Find an artifact by distro.
    pub fn find(&self,
        channel: &Channel,
        platform: &Platform,
        arch: &Arch) -> Option<&Artifact> {
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
}

/// Release information for a platform.
#[derive(Debug, Serialize, Deserialize)]
pub struct PlatformRelease {
    /// Release channels for the GUI.
    #[serde(flatten)]
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
    use anyhow::Result;
        
    /*
    static JSON:&str = r#""#;
    #[test]
    fn test_serde() -> Result<()> {
        let info: ReleaseInfo = serde_json::from_str(JSON)?;
        let artifact = &info.gui.find(&Channel::Beta, &Platform::MacOS, &Arch::Universal);
        assert!(artifact.is_some());
        Ok(())
    }
    */
}
