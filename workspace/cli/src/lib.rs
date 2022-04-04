use std::str::FromStr;
use uuid::Uuid;

pub const LOG_TARGET: &str = "sos3";

#[derive(Debug)]
pub enum UuidOrName {
    Uuid(Uuid),
    Name(String),
}

impl FromStr for UuidOrName {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(uuid) = Uuid::parse_str(s) {
            Ok(Self::Uuid(uuid))
        } else {
            Ok(Self::Name(s.to_string()))
        }
    }
}

pub mod input;
pub mod new;
pub mod user;
pub mod vault;
