use anyhow::Result;
use sos_core::AccountId;
use sos_net::pairing::ServerPairUrl;
use url::Url;

const SERVER: &str = "http://192.168.1.8:5053";

#[test]
fn pair_server_url() -> Result<()> {
    let mock_account_id = AccountId::random();
    let mock_url = Url::parse(&format!("{}/foo?bar=baz+qux", SERVER))?;
    let mock_key = vec![1, 2, 3, 4];
    let share = ServerPairUrl::new(
        mock_account_id.clone(),
        mock_url.clone(),
        mock_key.clone(),
    );
    let share_url: Url = share.into();
    let share_url = share_url.to_string();
    let parsed_share: ServerPairUrl = share_url.parse()?;
    assert_eq!(&mock_account_id, parsed_share.account_id());
    assert_eq!(&mock_url, parsed_share.server());
    assert_eq!(&mock_key, parsed_share.public_key());
    Ok(())
}

#[test]
fn pair_server_url_errors() -> Result<()> {
    // Not data:// scheme
    assert!(SERVER.parse::<ServerPairUrl>().is_err());
    // Invalid path for MIME type info
    assert!("data://image/png,sos-pair"
        .parse::<ServerPairUrl>()
        .is_err());
    // No `aid` query string
    assert!("data://text/plain,sos-pair"
        .parse::<ServerPairUrl>()
        .is_err());
    // No server `url` query string
    assert!("data://text/plain,sos-pair?aid=0x020172140827f060693a1c9a2f5d9639ec299d4c"
        .parse::<ServerPairUrl>()
        .is_err());
    // No noise public `key` query string
    assert!("data://text/plain,sos-pair?aid=0x020172140827f060693a1c9a2f5d9639ec299d4c&url=http://localhost"
        .parse::<ServerPairUrl>()
        .is_err());
    // No pre-shared private `psk` query string
    assert!("data://text/plain,sos-pair?aid=0x020172140827f060693a1c9a2f5d9639ec299d4c&url=http://localhost&key=0xff"
        .parse::<ServerPairUrl>()
        .is_err());
    // The `psk` query string is not 32 bytes
    assert!("data://text/plain,sos-pair?aid=0x020172140827f060693a1c9a2f5d9639ec299d4c&url=http://localhost&key=0xff&psk=0xff"
        .parse::<ServerPairUrl>()
        .is_err());

    Ok(())
}
