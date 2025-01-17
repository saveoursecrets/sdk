use super::get_vault_entry;
use anyhow::Result;
use binary_stream::futures::{BinaryReader, BinaryWriter};
use sos_core::encoding::encoding_options;
use sos_sdk::prelude::*;
use sos_test_utils::mock;
use std::io::Cursor;
use tokio::io::{BufReader, BufWriter};

/// Test encoding and decoding a vault row.
#[tokio::test]
async fn vault_writer_encode_decode_row() -> Result<()> {
    let (encryption_key, _, _) = mock::encryption_key()?;
    let (_temp, vault, _) = mock::vault_file().await?;

    let secret_label = "Test note";
    let secret_note = "Super secret note for you to read.";
    let (commit, entry) =
        get_vault_entry(&vault, &encryption_key, secret_label, secret_note)
            .await?;

    let secret_id = SecretId::new_v4();
    let row = VaultCommit(commit, entry);

    let mut buffer = Vec::new();
    let mut stream = BufWriter::new(Cursor::new(&mut buffer));
    let mut writer = BinaryWriter::new(&mut stream, encoding_options());
    Contents::encode_row(&mut writer, &secret_id, &row).await?;
    writer.flush().await?;

    let mut stream = BufReader::new(Cursor::new(&mut buffer));
    let mut reader = BinaryReader::new(&mut stream, encoding_options());

    let (_secret_id, decoded_row) = Contents::decode_row(&mut reader).await?;
    assert_eq!(row, decoded_row);

    Ok(())
}
