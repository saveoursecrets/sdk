//! Client implementations for the SPOT (Single Point of Truth) 
//! networking mode.

/// Client implementations that write to disc.
pub mod file {
    use sos_core::{wal::file::WalFile, patch::PatchFile, signer::Signer};
    use crate::client::node_cache::NodeCache;

    /// Client that communicates with a single server and 
    /// writes it's cache to disc.
    pub struct SpotFileClient<S> where S: Signer + Sync + Send + 'static {
        cache: NodeCache<S, WalFile, PatchFile>,
    }

    //let listener = ChangesListener::new(Arc::clone(&cache));
}

/// Client implementations that write to memory.
pub mod memory {
    use sos_core::{wal::memory::WalMemory, PatchMemory, signer::Signer};
    use crate::client::node_cache::NodeCache;

    /// Client that communicates with a single server and 
    /// writes it's cache to memory.
    pub struct SpotMemoryClient<S> where S: Signer + Sync + Send + 'static {
        cache: NodeCache<S, WalMemory, PatchMemory<'static>>,
    }
}

