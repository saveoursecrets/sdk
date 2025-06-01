#[cfg(all(test, feature = "mem-fs"))]
mod tests {
    use anyhow::Result;

    use std::ffi::OsString;
    use std::io::SeekFrom;
    use std::path::{PathBuf, MAIN_SEPARATOR};

    use crate::memory::{self as vfs, File, OpenOptions, Permissions};
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

    #[tokio::test]
    async fn memory_vfs() -> Result<()> {
        file_write_read().await?;
        file_append().await?;
        file_seek().await?;
        read_to_string().await?;
        metadata().await?;
        file_overwrite().await?;
        set_len().await?;
        absolute_file_write().await?;
        copy_file().await?;
        set_permissions().await?;

        write_read().await?;
        remove_file().await?;
        create_dir_remove_dir().await?;
        create_dir_all_remove_dir_all().await?;
        read_dir().await?;
        rename().await?;
        rename_replace_file().await?;

        canonicalize().await?;

        Ok(())
    }

    #[tokio::test]
    async fn rename_with_metadata() -> Result<()> {
        let from = "/foo/from.txt";
        let to = "/foo/to.txt";
        let data = "data to copy";

        vfs::create_dir("foo").await?;

        vfs::write(from, data.as_bytes()).await?;
        assert!(vfs::try_exists(from).await?);

        vfs::rename(from, to).await?;
        assert!(vfs::try_exists(to).await?);

        // list directory
        let mut dir_reader = vfs::read_dir("/foo").await?;
        while let Some(entry) = dir_reader.next_entry().await? {
            let entry_metadata = entry.metadata().await?;
            assert!(entry_metadata.is_file());
            assert_eq!(entry_metadata.len(), data.len() as u64);
        }

        Ok(())
    }

    #[tokio::test]
    async fn poll_complete_after_write() -> Result<()> {
        use futures::future::poll_fn;
        use std::pin::Pin;
        use tokio::io::{AsyncSeek, AsyncWriteExt};

        let path = "pos_after_write.txt";
        let mut f = File::create(path).await?;
        f.write_all(b"hello").await?; // 5 bytes
        f.flush().await?; // wait for the write to finish

        // Ask the file itself where it thinks the cursor is.
        let mut pinned = Pin::new(&mut f);
        let pos = poll_fn(|cx| pinned.as_mut().poll_complete(cx)).await?;

        // **BUG**: returns 0 with the current implementation
        assert_eq!(pos, 5, "cursor should sit just past the 5 written bytes");
        Ok(())
    }

    #[tokio::test]
    async fn poll_complete_after_set_len() -> Result<()> {
        use futures::future::poll_fn;
        use std::pin::Pin;
        use tokio::io::{AsyncSeek, AsyncSeekExt, AsyncWriteExt};

        let path = "pos_after_set_len.txt";
        let mut f = File::create(path).await?;
        f.write_all(b"abcdef").await?; // 6 bytes
        f.flush().await?;
        f.seek(std::io::SeekFrom::Start(2)).await?; // move to byte 2

        f.set_len(100).await?; // extend – should *not* move the cursor

        let mut pinned = Pin::new(&mut f);
        let pos = poll_fn(|cx| pinned.as_mut().poll_complete(cx)).await?;

        // **BUG**: current code reports 0 instead of 2
        assert_eq!(pos, 2, "set_len must preserve the current offset");
        Ok(())
    }

    #[tokio::test]
    async fn seek_after_pending_write() -> Result<()> {
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};

        let path = "seek_after_pending.txt";
        let mut f = File::create(path).await?;
        f.write_all(b"xyz").await?; // leaves an in-flight write

        // Try to find out where we are without an explicit flush.
        // Tokio’s real File lets this succeed; our version currently errors.
        let pos = f.seek(std::io::SeekFrom::Current(0)).await;

        // **BUG**: expect Ok(3), get Err(other operation is pending)
        assert_eq!(
            pos.unwrap(),
            3,
            "seek should wait for the write to finish"
        );
        Ok(())
    }

    async fn file_write_read() -> Result<()> {
        let path = "test.txt";
        let contents = "Mock content";

        let mut fd = File::create(path).await?;
        fd.write_all(contents.as_bytes()).await?;
        fd.flush().await?;
        assert!(vfs::try_exists(path).await?);

        let mut file_contents = Vec::new();
        let mut fd = File::open(path).await?;
        fd.read_to_end(&mut file_contents).await?;
        assert_eq!(contents.as_bytes(), &file_contents);

        vfs::remove_file(path).await?;

        Ok(())
    }

    async fn file_append() -> Result<()> {
        let path = "test.txt";
        vfs::write(path, "one".as_bytes()).await?;

        let mut fd = OpenOptions::new()
            .write(true)
            .append(true)
            .open(path)
            .await?;
        fd.write_all("two".as_bytes()).await?;
        fd.flush().await?;

        let file_contents = vfs::read(path).await?;
        assert_eq!("onetwo".as_bytes(), &file_contents);

        vfs::remove_file(path).await?;

        Ok(())
    }

    async fn file_seek() -> Result<()> {
        let path = "test.txt";
        vfs::write(path, "one".as_bytes()).await?;

        let mut fd = OpenOptions::new().write(true).open(path).await?;
        fd.seek(SeekFrom::End(0)).await?;
        fd.write_all("two".as_bytes()).await?;
        fd.flush().await?;

        fd.seek(SeekFrom::Start(1)).await?;
        let mut buf = [0; 2];
        fd.read_exact(&mut buf).await?;

        let val = std::str::from_utf8(&buf).unwrap();
        assert_eq!("ne", val);

        let file_contents = vfs::read(path).await?;
        assert_eq!("onetwo".as_bytes(), &file_contents);

        vfs::remove_file(path).await?;

        Ok(())
    }

    async fn read_to_string() -> Result<()> {
        let path = "test.txt";
        let contents = "Mock content";
        vfs::write(path, contents.as_bytes()).await?;
        assert!(vfs::try_exists(path).await?);

        let file_contents = vfs::read_to_string(path).await?;
        assert_eq!(contents, &file_contents);

        vfs::remove_file(&path).await?;
        Ok(())
    }

    async fn metadata() -> Result<()> {
        let path = "test.txt";
        let contents = "Mock content";
        vfs::write(path, contents.as_bytes()).await?;
        assert!(vfs::try_exists(path).await?);

        let metadata = vfs::metadata(path).await?;
        assert_eq!(contents.len(), metadata.len() as usize);
        assert!(metadata.is_file());

        let dir_path = "test-dir";
        vfs::create_dir(dir_path).await?;

        let metadata = vfs::metadata(dir_path).await?;
        assert_eq!(0, metadata.len() as usize);
        assert!(metadata.is_dir());

        vfs::remove_file(path).await?;
        vfs::remove_dir(dir_path).await?;
        Ok(())
    }

    async fn file_overwrite() -> Result<()> {
        let path = "test.txt";
        let one = "one";
        let two = "two";

        vfs::write(path, one.as_bytes()).await?;
        let contents = vfs::read_to_string(path).await?;
        assert_eq!(one, &contents);

        vfs::write(path, two.as_bytes()).await?;
        let contents = vfs::read_to_string(path).await?;
        assert_eq!(two, &contents);

        vfs::remove_file(path).await?;

        Ok(())
    }

    async fn set_len() -> Result<()> {
        let path = "test.txt";

        let fd = File::create(path).await?;
        // Extend length with zeroes
        fd.set_len(1024).await?;

        let metadata = fd.metadata().await?;
        assert_eq!(1024, metadata.len());

        // Truncate length
        fd.set_len(512).await?;

        let metadata = fd.metadata().await?;
        assert_eq!(512, metadata.len());

        vfs::remove_file(path).await?;

        Ok(())
    }

    async fn absolute_file_write() -> Result<()> {
        let parent = "/foo/bar/baz";
        vfs::create_dir_all(parent).await?;
        assert!(vfs::try_exists(parent).await?);

        let file = format!("{}/qux.vault", parent);

        vfs::write(&file, "mock").await?;
        assert!(vfs::try_exists(&file).await?);

        vfs::remove_dir_all("/foo").await?;

        Ok(())
    }

    async fn copy_file() -> Result<()> {
        let from = "from.txt";
        let to = "to.txt";
        let data = "data to copy";

        vfs::write(from, data.as_bytes()).await?;
        assert!(vfs::try_exists(from).await?);

        // Copy to same path is a noop
        assert!(vfs::copy(from, from).await.is_ok());

        vfs::copy(from, to).await?;
        assert!(vfs::try_exists(to).await?);

        let file_contents = vfs::read(to).await?;
        assert_eq!(data.as_bytes(), &file_contents);

        // Trigger the code path that overwrites an existing file
        vfs::copy(from, to).await?;

        vfs::remove_file(from).await?;
        vfs::remove_file(to).await?;

        Ok(())
    }

    async fn set_permissions() -> Result<()> {
        let path = "test.txt";

        vfs::write(path, "mock").await?;
        assert!(vfs::try_exists(path).await?);

        let mut perm: Permissions = Default::default();
        perm.set_readonly(true);

        vfs::set_permissions(path, perm).await?;
        assert!(vfs::metadata(path).await?.permissions().readonly());

        vfs::remove_file(path).await?;

        Ok(())
    }

    async fn write_read() -> Result<()> {
        let path = "test.txt";
        let contents = b"Mock content".to_vec();
        vfs::write(path, &contents).await?;

        assert!(vfs::try_exists(path).await?);

        let file_contents = vfs::read(path).await?;
        assert_eq!(&contents, &file_contents);

        vfs::remove_file(path).await?;
        Ok(())
    }

    async fn remove_file() -> Result<()> {
        let path = "test.txt";
        let contents = b"Mock content".to_vec();
        vfs::write(path, &contents).await?;

        vfs::remove_file(path).await?;
        assert!(!vfs::try_exists(path).await?);
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
            PathBuf::from("/read-dir/abc.txt"),
            first.as_ref().unwrap().path()
        );
        assert!(first.as_ref().unwrap().file_type().await?.is_file());

        let second = dir_reader.next_entry().await?;
        assert_eq!(
            OsString::from("def.txt"),
            second.as_ref().unwrap().file_name()
        );
        assert_eq!(
            PathBuf::from("/read-dir/def.txt"),
            second.as_ref().unwrap().path()
        );
        assert!(second.as_ref().unwrap().file_type().await?.is_file());

        let third = dir_reader.next_entry().await?;
        assert_eq!(
            OsString::from("ghi"),
            third.as_ref().unwrap().file_name()
        );
        assert_eq!(
            PathBuf::from("/read-dir/ghi"),
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

    async fn canonicalize() -> Result<()> {
        assert!(vfs::canonicalize("").await.is_err());
        assert_eq!(
            PathBuf::from(MAIN_SEPARATOR.to_string()),
            vfs::canonicalize(MAIN_SEPARATOR.to_string()).await?
        );

        vfs::create_dir("baz").await?;
        assert!(vfs::try_exists("baz").await?);
        vfs::create_dir_all("foo/bar/qux").await?;
        assert!(vfs::try_exists("foo").await?);
        assert!(vfs::try_exists("foo/bar").await?);
        assert!(vfs::try_exists("foo/bar/qux").await?);

        assert_eq!(PathBuf::from("/"), vfs::canonicalize("foo/..").await?,);

        assert_eq!(
            PathBuf::from("/foo"),
            vfs::canonicalize("foo/././.").await?,
        );

        assert_eq!(
            PathBuf::from("/baz"),
            vfs::canonicalize("foo/../baz").await?,
        );

        assert_eq!(
            PathBuf::from("/foo/bar/qux"),
            vfs::canonicalize("foo/../foo/bar/qux").await?,
        );

        assert_eq!(
            PathBuf::from("/"),
            vfs::canonicalize("foo/bar/../..").await?,
        );

        assert_eq!(
            PathBuf::from("/foo/bar/qux"),
            vfs::canonicalize("foo/bar/../../foo/bar/qux").await?,
        );

        Ok(())
    }
}
