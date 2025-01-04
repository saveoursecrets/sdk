use anyhow::Result;
use sos_password::diceware::generate_passphrase;
use sos_sdk::crypto::*;

fn assert_key_length(kdf: &KeyDerivation) -> Result<()> {
    let salt = KeyDerivation::generate_salt();
    let deriver = kdf.deriver();
    let (passphrase, _) = generate_passphrase()?;
    let private_key = deriver.derive(&passphrase, &salt, None)?;
    assert_eq!(32, private_key.as_ref().len());
    Ok(())
}

#[test]
fn kdf_argon_2_id() -> Result<()> {
    let kdf = KeyDerivation::Argon2Id;
    assert_key_length(&kdf)
}

#[test]
fn kdf_balloon_hash() -> Result<()> {
    let kdf = KeyDerivation::BalloonHash;
    assert_key_length(&kdf)
}
