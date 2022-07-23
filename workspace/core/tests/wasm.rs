use wasm_bindgen_test::*;
use sos_core::{encode, decode, Timestamp};

#[wasm_bindgen_test]
fn timestamp_encode() {
    let timestamp: Timestamp = Default::default();
    let buffer = encode(&timestamp).unwrap();
    let _timestamp: Timestamp = decode(&buffer).unwrap();
}
