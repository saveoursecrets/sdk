//! Network aware user storage and search index.
use std::{
    collections::HashMap,
    io::{Read, Seek},
    path::{Path, PathBuf},
    sync::Arc,
};

use sos_sdk::{
    account::{
        archive::Inventory, AccountBackup, AccountInfo, AuthenticatedUser,
        DelegatedPassphrase, ExtractFilesLocation, LocalAccounts, Login,
        RestoreOptions,
    },
    decode, encode,
    events::SyncEvent,
    search::{DocumentCount, SearchIndex},
    signer::ecdsa::Address,
    storage::{EncryptedFile, FileStorage, StorageDirs},
    vault::{
        secret::{Secret, SecretData, SecretId, SecretMeta, SecretType},
        Gatekeeper, Summary, Vault, VaultAccess, VaultFileAccess, VaultId,
    },
    Timestamp,
};

use parking_lot::RwLock as SyncRwLock;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

use crate::client::{
    provider::{BoxedProvider, ProviderFactory},
    Error, Result,
};

#[cfg(feature = "peer")]
use crate::peer::convert_libp2p_identity;

#[cfg(feature = "device")]
mod devices;

mod file_manager;
mod search_index;
mod user_storage;

#[cfg(feature = "device")]
pub use devices::DeviceManager;

#[cfg(feature = "migrate")]
pub use sos_migrate::{
    import::{ImportFormat, ImportTarget},
    Convert,
};

pub use search_index::{ArchiveFilter, DocumentView, QueryFilter, UserIndex};
pub use user_storage::{
    AccountData, ContactImportProgress, UserStatistics, UserStorage,
};
