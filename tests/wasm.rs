#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use sos_sdk::{
        decode, encode,
        vault::{Summary, Vault},
        vfs, Timestamp,
    };
    use std::path::PathBuf;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::*;

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

    /*
    #[wasm_bindgen_test]
    async fn event_log_memory_parse() {
        use std::path::PathBuf;
        let buffer = include_bytes!("fixtures/simple-vault.sos");
        let mut event_log = EventLogFile::new(PathBuf::from("")).unwrap();
        event_log.write_buffer(buffer.to_vec()).await.unwrap();
    }
    */
    
    /*
    #[wasm_bindgen_test]
    async fn vfs() {
        let path = PathBuf::from("test.txt");
        let contents = b"Mock content".to_vec();
        vfs::write(&path, &contents).await.expect("to write file");

        let file_contents = vfs::read(&path).await.expect("to read file");
        assert_eq!(&contents, &file_contents);

        vfs::remove_file(&path).await.expect("to remove file");
    }
    */
}
