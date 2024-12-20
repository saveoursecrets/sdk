include!(concat!(env!("OUT_DIR"), "/files.rs"));

#[cfg(feature = "files")]
mod files {
    use super::*;
    use crate::{
        decode_uuid, encode_uuid,
        sdk::{
            storage::files::{ExternalFile, ExternalFileName},
            vault::secret::SecretPath,
        },
        transfer::{FileSet, FileTransfersSet},
        Error, ProtoBinding, Result,
    };
    use indexmap::IndexSet;

    impl ProtoBinding for ExternalFile {
        type Inner = WireExternalFile;
    }

    impl TryFrom<WireExternalFile> for ExternalFile {
        type Error = Error;

        fn try_from(value: WireExternalFile) -> Result<Self> {
            let folder_id = decode_uuid(&value.folder_id)?;
            let secret_id = decode_uuid(&value.secret_id)?;
            let file_name: [u8; 32] =
                value.file_name.as_slice().try_into()?;
            Ok(Self::new(
                SecretPath(folder_id, secret_id),
                file_name.into(),
            ))
        }
    }

    impl From<ExternalFile> for WireExternalFile {
        fn from(value: ExternalFile) -> Self {
            let (owner, file_name): (SecretPath, ExternalFileName) =
                value.into();
            Self {
                folder_id: encode_uuid(&owner.0),
                secret_id: encode_uuid(&owner.1),
                file_name: file_name.as_ref().to_vec(),
            }
        }
    }

    impl ProtoBinding for FileSet {
        type Inner = WireFileSet;
    }

    impl TryFrom<WireFileSet> for FileSet {
        type Error = Error;

        fn try_from(value: WireFileSet) -> Result<Self> {
            let mut files = IndexSet::new();
            for file in value.files {
                files.insert(file.try_into()?);
            }
            Ok(Self(files))
        }
    }

    impl From<FileSet> for WireFileSet {
        fn from(value: FileSet) -> Self {
            Self {
                files: value.0.into_iter().map(|f| f.into()).collect(),
            }
        }
    }

    impl ProtoBinding for FileTransfersSet {
        type Inner = WireFileTransfersSet;
    }

    impl TryFrom<WireFileTransfersSet> for FileTransfersSet {
        type Error = Error;

        fn try_from(value: WireFileTransfersSet) -> Result<Self> {
            let uploads: FileSet = value.uploads.unwrap().try_into()?;
            let downloads: FileSet = value.downloads.unwrap().try_into()?;
            Ok(Self { uploads, downloads })
        }
    }

    impl From<FileTransfersSet> for WireFileTransfersSet {
        fn from(value: FileTransfersSet) -> Self {
            Self {
                uploads: Some(value.uploads.into()),
                downloads: Some(value.downloads.into()),
            }
        }
    }
}
