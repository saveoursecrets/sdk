use anyhow::Result;
use sos_core::AccountId;
use sos_net::pairing::ServerPairUrl;
use url::Url;

#[test]
fn server_pair_url() -> Result<()> {
    let mock_account_id = AccountId::random();
    let mock_url = Url::parse("http://192.168.1.8:5053/foo?bar=baz+qux")?;
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
