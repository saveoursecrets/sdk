use anyhow::Result;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sos_recovery::*;
use sos_sdk::{decode, encode, vault::VaultId};
use sos_signer::{ecdsa::SingleParty, Signer};

#[derive(Serialize, Deserialize)]
pub struct MockUserInfo {
    email: String,
}

fn mock_data() -> (VaultId, &'static str, RecoveryData) {
    let mock_id = VaultId::new_v4();
    let mock_password = "mock-password";
    let mut data: RecoveryData = Default::default();
    data.vaults_mut()
        .insert(mock_id.clone(), mock_password.to_string().into());
    (mock_id, mock_password, data)
}

#[tokio::test]
pub async fn recovery_symmetric() -> Result<()> {
    let (mock_id, mock_password, data) = mock_data();
    let signer = SingleParty::new_random();
    let threshold = 2;
    let limit = 3;
    let options = RecoveryOptions::new(threshold, limit, None, None);

    let (pack, recovery) =
        RecoveryPack::encrypt(&data, &signer, options).await?;
    assert_eq!(3, recovery.shares.len());

    // Verify encoding and decoding
    let encoded_pack = encode(&pack).await?;
    let pack: RecoveryPack = decode(&encoded_pack).await?;

    // Not enough shares
    let less_than_threshold = RecoveryShares {
        shares: recovery.shares[0..1].to_vec(),
    };
    assert!(pack.decrypt(&less_than_threshold).await.is_err());

    // Number of shares meets the threshold (2)
    let recovery_shares = RecoveryShares {
        shares: recovery.shares[0..2].to_vec(),
    };
    let (recovered_signer, recovered_data) =
        pack.decrypt(&recovery_shares).await?;
    let recovered_password = recovered_data.vaults().get(&mock_id).unwrap();
    assert_eq!(signer.to_bytes(), recovered_signer.to_bytes());
    assert_eq!(mock_password, recovered_password.expose_secret());

    Ok(())
}

#[tokio::test]
pub async fn recovery_group() -> Result<()> {
    let (mock_id, mock_password, data) = mock_data();
    let signer = SingleParty::new_random();
    let (group, secret_shares) = RecoveryGroup::<MockUserInfo>::builder()
        .add_participant(RecoveryParticipant::new(MockUserInfo {
            email: "user1@example.com".to_string(),
        }))
        .add_participant(RecoveryParticipant::new(MockUserInfo {
            email: "user2@example.com".to_string(),
        }))
        .add_participant(RecoveryParticipant::new(MockUserInfo {
            email: "user3@example.com".to_string(),
        }))
        .threshold(2)
        .signer(signer.clone())
        .data(data.clone())
        .build()
        .await?;

    assert_eq!(3, group.limit());
    assert_eq!(2, group.threshold());

    let recovery_shares = RecoveryShares {
        shares: secret_shares.shares[0..2].to_vec(),
    };

    let pack: RecoveryPack = group.into();
    let (recovered_signer, recovered_data) =
        pack.decrypt(&recovery_shares).await?;

    let recovered_password = recovered_data.vaults().get(&mock_id).unwrap();
    assert_eq!(signer.to_bytes(), recovered_signer.to_bytes());
    assert_eq!(mock_password, recovered_password.expose_secret());

    Ok(())
}
