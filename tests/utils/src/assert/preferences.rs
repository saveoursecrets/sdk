use std::{collections::HashMap, net::SocketAddr};

use sos_preferences::{Preference, Preferences};
use sos_protocol::network_client::NetworkConfig;

/// Assert on the operations for a preferences collection.
pub async fn assert_preferences<E>(
    prefs: &mut Preferences<E>,
) -> anyhow::Result<()>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_preferences::Error>
        + Send
        + Sync
        + 'static,
{
    // Create preferences
    prefs.insert("mock.bool".to_owned(), true.into()).await?;

    prefs.insert("mock.int".to_owned(), (-15i64).into()).await?;

    prefs
        .insert("mock.double".to_owned(), (2.54f64).into())
        .await?;

    prefs
        .insert("mock.string".to_owned(), "message".to_owned().into())
        .await?;
    let list = vec!["item-1".to_owned(), "item-2".to_owned()];
    prefs
        .insert("mock.string-list".to_owned(), list.into())
        .await?;

    // Update a preferenece
    prefs.insert("mock.bool".to_owned(), false.into()).await?;

    let mut complex = HashMap::new();
    complex.insert("foo".to_string(), "bar".to_string());
    let complex = serde_json::to_value(&complex)?;
    prefs.insert("mock.map".to_owned(), complex.into()).await?;

    let mut net_config = NetworkConfig::default();
    net_config
        .resolve_addrs
        .insert("foo.local".to_owned(), "192.168.1.33:8080".parse()?);
    let net_config = serde_json::to_value(&net_config)?;
    prefs
        .insert("mock.network.config".to_owned(), net_config.into())
        .await?;

    // Retrieve preferences
    let missing = prefs.get_unchecked("mock.non-existent");
    assert!(missing.is_none());

    let boolean = prefs.get_bool("mock.bool")?;
    assert!(matches!(boolean, Some(Preference::Bool(_))));

    let int = prefs.get_number("mock.int")?;
    assert!(matches!(int, Some(Preference::Number(_))));

    let double = prefs.get_number("mock.double")?;
    assert!(matches!(double, Some(Preference::Number(_))));

    let string = prefs.get_string("mock.string")?;
    assert!(matches!(string, Some(Preference::String(_))));

    let string_list = prefs.get_string_list("mock.string-list")?;
    assert!(matches!(string_list, Some(Preference::StringList(_))));

    let json_value = prefs.get_json_value("mock.map")?;
    assert!(matches!(json_value, Some(Preference::Json(_))));

    let net_config = prefs.get_json_value("mock.network.config")?;

    if let Some(Preference::Json(val)) = net_config {
        let net_config: NetworkConfig = serde_json::from_value(val.clone())?;
        assert_eq!(
            "192.168.1.33:8080".parse::<SocketAddr>().ok().as_ref(),
            net_config.resolve_addrs.get("foo.local")
        );
    } else {
        panic!("expecting JSON preference");
    }

    // Remove preferences
    let removed = prefs.remove("mock.bool").await?;
    assert!(matches!(removed, Some(Preference::Bool(false))));

    // Clear preferences
    prefs.clear().await?;

    // Reload
    prefs.load().await?;

    let items = prefs.iter().collect::<Vec<_>>();

    assert!(items.is_empty());

    Ok(())
}
