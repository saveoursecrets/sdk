use anyhow::Result;

use std::{ffi::OsString, io::SeekFrom};

use sos_sdk::vfs::{self, File, FileType, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[tokio::test]
async fn integration_memory_vfs() -> Result<()> {
    file_write_read().await?;
    read_to_string().await?;

    write_read().await?;
    remove_file().await?;
    create_dir_remove_dir().await?;
    create_dir_all_remove_dir_all().await?;
    read_dir().await?;
    rename().await?;
    rename_replace_file().await?;

    //vfs::write("foo/bar/qux.txt", b"qux").await?;

    Ok(())
}

async fn file_write_read() -> Result<()> {
    let path = PathBuf::from("test.txt");
    let contents = "Mock content";

    let mut fd = File::create(&path).await?;
    fd.write_all(contents.as_bytes()).await?;
    fd.flush().await?;
    assert!(vfs::try_exists(&path).await?);

    let mut file_contents = Vec::new();
    let mut fd = File::open(&path).await?;
    fd.seek(SeekFrom::Start(0)).await?;
    fd.read_to_end(&mut file_contents).await?;
    assert_eq!(contents.as_bytes(), &file_contents);

    vfs::remove_file(&path).await?;

    Ok(())
}

async fn read_to_string() -> Result<()> {
    let path = PathBuf::from("test.txt");
    let contents = "Mock content";
    vfs::write(&path, contents.as_bytes()).await?;
    assert!(vfs::try_exists(&path).await?);

    let file_contents = vfs::read_to_string(&path).await?;
    assert_eq!(contents, &file_contents);

    vfs::remove_file(&path).await?;
    Ok(())
}

async fn write_read() -> Result<()> {
    let path = PathBuf::from("test.txt");
    let contents = b"Mock content".to_vec();
    vfs::write(&path, &contents).await?;

    assert!(vfs::try_exists(&path).await?);

    let file_contents = vfs::read(&path).await?;
    assert_eq!(&contents, &file_contents);

    vfs::remove_file(&path).await?;
    Ok(())
}

async fn remove_file() -> Result<()> {
    let path = PathBuf::from("test.txt");
    let contents = b"Mock content".to_vec();
    vfs::write(&path, &contents).await?;

    vfs::remove_file(&path).await?;
    assert!(!vfs::try_exists(&path).await?);
    Ok(())
}

async fn create_dir_remove_dir() -> Result<()> {
    vfs::create_dir("foo").await?;
    assert!(vfs::try_exists("foo").await?);

    vfs::remove_dir("foo").await?;
    assert!(!vfs::try_exists("foo").await?);
    Ok(())
}

async fn create_dir_all_remove_dir_all() -> Result<()> {
    vfs::create_dir_all("foo/bar").await?;
    assert!(vfs::try_exists("foo").await?);
    assert!(vfs::try_exists("foo/bar").await?);

    vfs::remove_dir_all("foo").await?;
    assert!(!vfs::try_exists("foo/bar").await?);
    assert!(!vfs::try_exists("foo").await?);
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

    vfs::remove_dir_all("read-dir").await?;

    Ok(())
}

async fn rename() -> Result<()> {
    vfs::create_dir("foo").await?;
    let exists = vfs::try_exists("foo").await?;
    assert!(exists);

    vfs::rename("foo", "bar").await?;
    assert!(!vfs::try_exists("foo").await?);
    assert!(vfs::try_exists("bar").await?);

    vfs::remove_dir_all("bar").await?;

    Ok(())
}

async fn rename_replace_file() -> Result<()> {
    vfs::write("foo.txt", b"foo").await?;
    vfs::write("bar.txt", b"bar").await?;
    assert!(vfs::try_exists("foo.txt").await?);
    assert!(vfs::try_exists("bar.txt").await?);

    vfs::rename("foo.txt", "bar.txt").await?;

    assert!(!vfs::try_exists("foo.txt").await?);
    assert!(vfs::try_exists("bar.txt").await?);

    Ok(())
}
