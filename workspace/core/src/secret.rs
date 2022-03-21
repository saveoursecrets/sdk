//! Types used to represent vault meta data and secrets.

use anyhow::Result;
use binary_rw::{BinaryReader, BinaryWriter};

use std::collections::BTreeMap;
use uuid::Uuid;

use crate::traits::{Decode, Encode};

/// Unencrypted vault meta data.
#[derive(Default)]
pub struct MetaData {
    label: String,
    secrets: BTreeMap<String, Uuid>,
}

impl MetaData {
    /// Get the vault label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get the vault label.
    pub fn set_label(&mut self, label: String) {
        self.label = label;
    }
}

impl Encode for MetaData {
    fn encode(&self, writer: &mut BinaryWriter) -> Result<()> {
        writer.write_string(&self.label)?;
        writer.write_usize(self.secrets.len())?;
        for (key, value) in self.secrets.iter() {
            writer.write_string(key)?;
            writer.write_string(value.to_string())?;
        }
        Ok(())
    }
}

impl Decode for MetaData {
    fn decode(&mut self, reader: &mut BinaryReader) -> Result<()> {
        self.label = reader.read_string()?;
        let secrets_len = reader.read_usize()?;
        for _ in 0..secrets_len {
            let key = reader.read_string()?;
            let value = Uuid::parse_str(&reader.read_string()?)?;
            self.secrets.insert(key, value);
        }
        Ok(())
    }
}
