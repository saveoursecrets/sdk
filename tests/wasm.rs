#[cfg(target_arch = "wasm32")]
mod wasm_tests {
    use sos_core::{decode, encode, Timestamp};
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn timestamp_encode() {
        let timestamp: Timestamp = Default::default();
        let buffer = encode(&timestamp).unwrap();
        let _timestamp: Timestamp = decode(&buffer).unwrap();
    }
}
