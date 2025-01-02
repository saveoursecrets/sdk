use anyhow::Result;
use sos_artifact::*;
use time::OffsetDateTime;

static JSON: &str = include_str!("../../../fixtures/releases.json");

#[test]
fn artifact_releases_serde() -> Result<()> {
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
    let artifact =
        &info
            .gui
            .find(&Channel::Beta, &Platform::MacOS, &Arch::Universal);
    assert!(artifact.is_some());

    let artifact =
        &info
            .cli
            .find(&Channel::Beta, &Platform::MacOS, &Arch::Aarch64);
    assert!(artifact.is_some());

    Ok(())
}
