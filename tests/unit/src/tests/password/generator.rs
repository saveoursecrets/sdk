use anyhow::Result;
use secrecy::ExposeSecret;
use sos_password::generator::PasswordBuilder;

#[test]
fn passgen_memorable() -> Result<()> {
    let generator = PasswordBuilder::new_memorable(3);
    let result = generator.one()?;
    assert_eq!(20, result.password.expose_secret().len());
    Ok(())
}

#[test]
fn passgen_alpha() -> Result<()> {
    let generator = PasswordBuilder::new_alpha(12);
    let result = generator.one()?;
    assert_eq!(generator.len(), result.password.expose_secret().len());
    Ok(())
}

#[test]
fn passgen_numeric() -> Result<()> {
    let generator = PasswordBuilder::new_numeric(12);
    let result = generator.one()?;
    assert_eq!(generator.len(), result.password.expose_secret().len());
    Ok(())
}

#[test]
fn passgen_alphanumeric() -> Result<()> {
    let generator = PasswordBuilder::new_alpha_numeric(12);
    let result = generator.one()?;
    assert_eq!(generator.len(), result.password.expose_secret().len());
    Ok(())
}

#[test]
fn passgen_ascii_printable() -> Result<()> {
    let generator = PasswordBuilder::new_ascii_printable(12);
    let result = generator.one()?;
    assert_eq!(generator.len(), result.password.expose_secret().len());
    Ok(())
}

#[test]
fn passgen_ascii_printable_long() -> Result<()> {
    let generator = PasswordBuilder::new_ascii_printable(32);
    let result = generator.one()?;
    assert_eq!(generator.len(), result.password.expose_secret().len());
    Ok(())
}

#[test]
fn passgen_diceware() -> Result<()> {
    let generator = PasswordBuilder::new_diceware(6);
    let result = generator.one()?;
    let words: Vec<String> = result
        .password
        .expose_secret()
        .split(' ')
        .map(|s| s.to_owned())
        .collect();
    assert_eq!(generator.len(), words.len());
    Ok(())
}

#[test]
fn passgen_generate() -> Result<()> {
    let generator = PasswordBuilder::new_ascii_printable(12);
    let count = 5;
    let passwords = generator.many(count)?;
    assert_eq!(count, passwords.len());
    for result in passwords {
        assert_eq!(generator.len(), result.password.expose_secret().len());
    }
    Ok(())
}
