#[cfg(all(test, target_arch = "wasm32"))]
mod vfs_tests {
    use sos_sdk::{
        vfs,
    };
    use std::path::PathBuf;

    #[tokio::test]
    async fn vfs_read_write() {
        let path = PathBuf::from("test.txt");
        let contents = b"Mock content".to_vec();
        vfs::write(&path, &contents).await.expect("to write file");

        let file_contents = vfs::read(&path).await.expect("to read file");
        assert_eq!(&contents, &file_contents);

        vfs::remove_file(&path).await.expect("to remove file");
    }
}
