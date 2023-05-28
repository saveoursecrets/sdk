use anyhow::Result;

use std::ffi::OsString;

use sos_sdk::vfs::{self, FileType, PathBuf};

#[tokio::test]
async fn integration_memory_vfs() -> Result<()> {
    write_read().await?;
    remove_file().await?;
    create_dir_remove_dir().await?;
    create_dir_all_remove_dir_all().await?;
    read_dir().await?;

    //vfs::write("foo/bar/qux.txt", b"qux").await?;

    Ok(())
}

async fn write_read() -> Result<()> {
    let path = PathBuf::from("test.txt");
    let contents = b"Mock content".to_vec();
    vfs::write(&path, &contents).await?;

    let exists = vfs::try_exists(&path).await?;
    assert!(exists);

    let file_contents = vfs::read(&path).await?;
    assert_eq!(&contents, &file_contents);
    Ok(())
}

async fn remove_file() -> Result<()> {
    let path = PathBuf::from("test.txt");
    let contents = b"Mock content".to_vec();
    vfs::write(&path, &contents).await?;

    vfs::remove_file(&path).await?;
    let exists = vfs::try_exists(&path).await?;
    assert!(!exists);
    Ok(())
}

async fn create_dir_remove_dir() -> Result<()> {
    vfs::create_dir("foo").await?;
    let exists = vfs::try_exists("foo").await?;
    assert!(exists);

    vfs::remove_dir("foo").await?;
    let exists = vfs::try_exists("foo").await?;
    assert!(!exists);
    Ok(())
}

async fn create_dir_all_remove_dir_all() -> Result<()> {
    vfs::create_dir_all("foo/bar").await?;
    let exists = vfs::try_exists("foo").await?;
    assert!(exists);
    let exists = vfs::try_exists("foo/bar").await?;
    assert!(exists);

    vfs::remove_dir_all("foo").await?;
    let exists = vfs::try_exists("foo/bar").await?;
    assert!(!exists);
    let exists = vfs::try_exists("foo").await?;
    assert!(!exists);
    Ok(())
}

async fn read_dir() -> Result<()> {
    let dir = "read-dir";
    vfs::create_dir(dir).await?;

    let one = b"one".to_vec();
    let two = b"two".to_vec();
    vfs::write("read-dir/abc.txt", &one).await?;
    vfs::write("read-dir/def.txt", &two).await?;
    vfs::create_dir("read-dir/ghi").await?;

    let mut dir_reader = vfs::read_dir(dir).await?;
    let first = dir_reader.next_entry().await?;

    assert_eq!(
        OsString::from("abc.txt"),
        first.as_ref().unwrap().file_name()
    );
    assert_eq!(
        PathBuf::from("read-dir/abc.txt"),
        first.as_ref().unwrap().path()
    );
    assert!(first.as_ref().unwrap().file_type().await?.is_file());

    let second = dir_reader.next_entry().await?;
    assert_eq!(
        OsString::from("def.txt"),
        second.as_ref().unwrap().file_name()
    );
    assert_eq!(
        PathBuf::from("read-dir/def.txt"),
        second.as_ref().unwrap().path()
    );
    assert!(second.as_ref().unwrap().file_type().await?.is_file());

    let third = dir_reader.next_entry().await?;
    assert_eq!(OsString::from("ghi"), third.as_ref().unwrap().file_name());
    assert_eq!(
        PathBuf::from("read-dir/ghi"),
        third.as_ref().unwrap().path()
    );
    assert!(third.as_ref().unwrap().file_type().await?.is_dir());

    Ok(())
}
