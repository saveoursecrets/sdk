pub mod common {
    include!(concat!(env!("OUT_DIR"), "/common.rs"));
}

pub mod scan {
    include!(concat!(env!("OUT_DIR"), "/scan.rs"));
}
