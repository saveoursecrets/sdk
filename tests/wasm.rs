#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use wasm_bindgen_test::*;
    use wasm_bindgen::prelude::*;
    use sos_core::{decode, encode, Timestamp, vault::{Vault, Summary}, wal::{memory::WalMemory, WalProvider}};

    /*
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = console)]
        fn log(s: &str);
    }

    #[doc(hidden)]
    #[macro_export]
    macro_rules! console_log {
        ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
    }
    */

    #[wasm_bindgen_test]
    fn vault_encode() {
        let vault: Vault = Default::default();
        let buffer = encode(&vault).unwrap();
        let decoded: Vault = decode(&buffer).unwrap();
        assert_eq!(vault, decoded);
    }

    #[wasm_bindgen_test]
    fn timestamp_encode() {
        let timestamp: Timestamp = Default::default();
        let buffer = encode(&timestamp).unwrap();
        let decoded: Timestamp = decode(&buffer).unwrap();
        assert_eq!(timestamp, decoded);
    }

    // FIXME: restore this test with a new fixture
    /*
    #[wasm_bindgen_test]
    fn wal_memory_parse() {
        use std::path::PathBuf;
        let buffer = include_bytes!("fixtures/simple-vault.wal");
        let mut wal = WalMemory::new(PathBuf::from("")).unwrap();
        wal.write_buffer(buffer.to_vec()).unwrap();
    }
    */
}
