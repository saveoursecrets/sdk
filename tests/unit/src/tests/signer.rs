use anyhow::Result;
use k256::ecdsa::{hazmat::SignPrimitive, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use sos_core::csprng;

#[test]
fn ecdsa_sign() -> Result<()> {
    // Generate a signature with recovery id
    let signing_key = SigningKey::random(&mut csprng());
    let message = b".well-known";
    let digest = Keccak256::digest(message);
    let (_signature, recid) = signing_key
        .as_nonzero_scalar()
        .try_sign_prehashed_rfc6979::<Keccak256>(
            digest.as_slice().into(),
            b"",
        )?;
    assert!(recid.is_some());
    Ok(())
}

#[test]
fn ecdsa_sign_recover() -> Result<()> {
    let signing_key = SigningKey::random(&mut csprng());
    let message = b".well-known";
    let digest = Keccak256::digest(message);
    let (signature, recid) = signing_key
        .as_nonzero_scalar()
        .try_sign_prehashed_rfc6979::<Keccak256>(
            digest.as_slice().into(),
            b"",
        )?;

    let verify_key = signing_key.verifying_key();

    // Recovery
    let recovered_key = VerifyingKey::recover_from_digest(
        Keccak256::new_with_prefix(message),
        &signature,
        recid.unwrap(),
    )?;

    assert_eq!(verify_key, &recovered_key);
    Ok(())
}
