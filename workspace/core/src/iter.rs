//! Traits and types for a generic file iterator.
use std::ops::Range;

use binary_stream::{
    BinaryReader, BinaryResult, Decode, Endian, ReadStream, SeekStream,
};

use crate::{
    constants::{
        AUDIT_IDENTITY, PATCH_IDENTITY, VAULT_IDENTITY, WAL_IDENTITY,
    },
    vault::Header,
    wal::WalItem,
    FileIdentity, Result, Timestamp,
};

#[cfg(not(target_arch = "wasm32"))]
use std::{fs::File, path::Path};

#[cfg(not(target_arch = "wasm32"))]
use binary_stream::FileStream;

/// Get an iterator for a vault file.
#[cfg(not(target_arch = "wasm32"))]
pub fn vault_iter<P: AsRef<Path>>(
    path: P,
) -> Result<ReadStreamIterator<VaultRecord>> {
    let content_offset = Header::read_content_offset(path.as_ref())?;
    ReadStreamIterator::<VaultRecord>::new_file(
        path.as_ref(),
        &VAULT_IDENTITY,
        true,
        Some(content_offset),
    )
}

/// Get an iterator for a vault buffer.
#[cfg(target_arch = "wasm32")]
pub fn vault_iter(
    buffer: Vec<u8>,
) -> Result<ReadStreamIterator<VaultRecord>> {
    let content_offset = Header::read_content_offset_slice(&buffer)?;
    ReadStreamIterator::<VaultRecord>::new_memory(
        buffer,
        &VAULT_IDENTITY,
        true,
        Some(content_offset),
    )
}

/// Get an iterator for a WAL file.
#[cfg(not(target_arch = "wasm32"))]
pub fn wal_iter<P: AsRef<Path>>(
    path: P,
) -> Result<ReadStreamIterator<WalFileRecord>> {
    ReadStreamIterator::<WalFileRecord>::new_file(
        path.as_ref(),
        &WAL_IDENTITY,
        true,
        None,
    )
}

/// Get an iterator for a WAL file.
#[cfg(target_arch = "wasm32")]
pub fn wal_iter(
    buffer: Vec<u8>,
) -> Result<ReadStreamIterator<WalFileRecord>> {
    ReadStreamIterator::<WalFileRecord>::new_memory(
        buffer,
        &WAL_IDENTITY,
        true,
        None,
    )
}

/// Get an iterator for a patch file.
#[cfg(not(target_arch = "wasm32"))]
pub fn patch_iter<P: AsRef<Path>>(
    path: P,
) -> Result<ReadStreamIterator<FileRecord>> {
    ReadStreamIterator::new_file(path.as_ref(), &PATCH_IDENTITY, false, None)
}

/// Get an iterator for a patch file.
#[cfg(target_arch = "wasm32")]
pub fn patch_iter(buffer: Vec<u8>) -> Result<ReadStreamIterator<FileRecord>> {
    ReadStreamIterator::new_memory(buffer, &PATCH_IDENTITY, false, None)
}

/// Get an iterator for an audit file.
#[cfg(not(target_arch = "wasm32"))]
pub fn audit_iter<P: AsRef<Path>>(
    path: P,
) -> Result<ReadStreamIterator<FileRecord>> {
    ReadStreamIterator::new_file(path.as_ref(), &AUDIT_IDENTITY, false, None)
}

/// Get an iterator for an audit file.
#[cfg(target_arch = "wasm32")]
pub fn audit_iter(buffer: Vec<u8>) -> Result<ReadStreamIterator<FileRecord>> {
    ReadStreamIterator::new_memory(buffer, &AUDIT_IDENTITY, false, None)
}

/// Trait for types yielded by the file iterator.
pub trait FileItem: Default + std::fmt::Debug + Decode {
    /// Get the byte offset for the record.
    fn offset(&self) -> &Range<usize>;

    /// Get the range for the record value.
    fn value(&self) -> &Range<usize>;

    /// Set the byte offset for the record.
    fn set_offset(&mut self, offset: Range<usize>);

    /// Set the range for the record value.
    fn set_value(&mut self, value: Range<usize>);

    /// Read the bytes for the value into an owned buffer.
    fn read_bytes<'a>(
        &self,
        reader: &mut BinaryReader<'a>,
    ) -> Result<Vec<u8>> {
        let value = self.value();
        let length = value.end - value.start;
        reader.seek(value.start)?;
        Ok(reader.read_bytes(length)?)
    }
}

/// Generic reference to a row in a file.
#[derive(Default, Debug)]
pub struct FileRecord {
    /// Byte offset for the record.
    offset: Range<usize>,
    /// The byte range for the value.
    value: Range<usize>,
}

impl FileItem for FileRecord {
    fn offset(&self) -> &Range<usize> {
        &self.offset
    }

    fn value(&self) -> &Range<usize> {
        &self.value
    }

    fn set_offset(&mut self, offset: Range<usize>) {
        self.offset = offset;
    }

    fn set_value(&mut self, value: Range<usize>) {
        self.value = value;
    }
}

impl Decode for FileRecord {
    fn decode(&mut self, _reader: &mut BinaryReader) -> BinaryResult<()> {
        Ok(())
    }
}

/// Reference to a row in a vault.
#[derive(Default, Debug)]
pub struct VaultRecord {
    /// Byte offset for the record.
    offset: Range<usize>,
    /// The byte range for the value.
    value: Range<usize>,
    /// The identifier for the secret.
    id: [u8; 16],
    /// The commit hash for the secret.
    commit: [u8; 32],
}

impl FileItem for VaultRecord {
    fn offset(&self) -> &Range<usize> {
        &self.offset
    }

    fn value(&self) -> &Range<usize> {
        &self.value
    }

    fn set_offset(&mut self, offset: Range<usize>) {
        self.offset = offset;
    }

    fn set_value(&mut self, value: Range<usize>) {
        self.value = value;
    }
}

impl VaultRecord {
    /// Get the identifier for the secret.
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// Get the commit hash for the secret.
    pub fn commit(&self) -> [u8; 32] {
        self.commit
    }
}

impl Decode for VaultRecord {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let id: [u8; 16] = reader.read_bytes(16)?.as_slice().try_into()?;
        let commit: [u8; 32] =
            reader.read_bytes(32)?.as_slice().try_into()?;

        self.id = id;
        self.commit = commit;
        Ok(())
    }
}

/// Reference to a row in the write ahead log.
#[derive(Default, Debug)]
pub struct WalFileRecord {
    /// Byte offset for the record.
    offset: Range<usize>,
    /// The byte range for the value.
    value: Range<usize>,
    /// The time the row was created.
    pub(crate) time: Timestamp,
    /// The commit hash for the previous row.
    pub(crate) last_commit: [u8; 32],
    /// The commit hash for the value.
    pub(crate) commit: [u8; 32],
}

impl FileItem for WalFileRecord {
    fn offset(&self) -> &Range<usize> {
        &self.offset
    }

    fn value(&self) -> &Range<usize> {
        &self.value
    }

    fn set_offset(&mut self, offset: Range<usize>) {
        self.offset = offset;
    }

    fn set_value(&mut self, value: Range<usize>) {
        self.value = value;
    }
}

impl WalItem for WalFileRecord {
    fn commit(&self) -> [u8; 32] {
        self.commit
    }

    fn last_commit(&self) -> [u8; 32] {
        self.last_commit
    }

    fn time(&self) -> &Timestamp {
        &self.time
    }
}

impl Decode for WalFileRecord {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        self.time.decode(&mut *reader)?;
        self.last_commit = reader.read_bytes(32)?.as_slice().try_into()?;
        self.commit = reader.read_bytes(32)?.as_slice().try_into()?;
        Ok(())
    }
}

/// Generic iterator for files.
pub struct ReadStreamIterator<T: FileItem> {
    /// Offset from the beginning of the stream where
    /// iteration should start and reverse iteration
    /// should complete.
    ///
    /// This is often the length of the identity magic
    /// bytes but in some cases may be specified when
    /// creating the iterator, for example, vault files
    /// have information in the file header so we need
    /// to pass the offset where the content starts.
    header_offset: usize,

    /// After decoding the row record is there a u32
    /// that is used to indicate the length of a a data
    /// blob for the row; if so then `value` will point
    /// to the data. This is used for lazy decoding such
    /// as in the case of WAL files where we need to read
    /// the commit hash(es) and timestamp most of the time
    /// but sometimes need to read the row data too.
    data_length_prefix: bool,
    /// The read stream.
    read_stream: Box<dyn ReadStream>,
    /// Byte offset for forward iteration.
    forward: Option<usize>,
    /// Byte offset for backward iteration.
    backward: Option<usize>,
    /// Marker type.
    marker: std::marker::PhantomData<T>,
}

impl<T: FileItem> ReadStreamIterator<T> {
    /// Create a new file iterator.
    #[cfg(not(target_arch = "wasm32"))]
    fn new_file<P: AsRef<Path>>(
        file_path: P,
        identity: &'static [u8],
        data_length_prefix: bool,
        header_offset: Option<usize>,
    ) -> Result<Self> {
        FileIdentity::read_file(file_path.as_ref(), identity)?;
        let mut read_stream: Box<dyn ReadStream> =
            Box::new(FileStream(File::open(file_path.as_ref())?));

        let header_offset = header_offset.unwrap_or_else(|| identity.len());
        read_stream.seek(header_offset)?;

        Ok(Self {
            header_offset,
            data_length_prefix,
            read_stream,
            forward: None,
            backward: None,
            marker: std::marker::PhantomData,
        })
    }

    /// Create a new memory iterator.
    pub fn new_memory(
        buffer: Vec<u8>,
        identity: &'static [u8],
        data_length_prefix: bool,
        header_offset: Option<usize>,
    ) -> Result<Self> {
        use binary_stream::MemoryStream;

        FileIdentity::read_slice(&buffer, identity)?;
        let stream: MemoryStream = buffer.into();
        let mut read_stream: Box<dyn ReadStream> = Box::new(stream);

        let header_offset = header_offset.unwrap_or_else(|| identity.len());
        read_stream.seek(header_offset)?;

        Ok(Self {
            header_offset,
            data_length_prefix,
            read_stream,
            forward: None,
            backward: None,
            marker: std::marker::PhantomData,
        })
    }

    /// Set the byte offset that constrains iteration.
    ///
    /// Useful when creating streams of log events.
    pub fn set_offset(&mut self, offset: usize) {
        self.header_offset = offset;
    }

    /// Helper to decode the row file record.
    fn read_row(
        reader: &mut BinaryReader,
        offset: Range<usize>,
        is_prefix: bool,
    ) -> Result<T> {
        let mut row: T = Default::default();

        row.decode(&mut *reader)?;

        if is_prefix {
            // The byte range for the row value.
            let value_len = reader.read_u32()?;

            let begin = reader.tell()?;
            let end = begin + value_len as usize;
            row.set_value(begin..end);
        } else {
            row.set_value(offset.start + 4..offset.end - 4);
        }

        row.set_offset(offset);

        Ok(row)
    }

    /// Attempt to read the next log row.
    fn read_row_next(&mut self) -> Result<T> {
        let row_pos = self.forward.unwrap();

        let mut reader =
            BinaryReader::new(&mut *self.read_stream, Endian::Big);
        reader.seek(row_pos)?;
        let row_len = reader.read_u32()?;

        // Position of the end of the row
        let row_end = row_pos + (row_len as usize + 8);

        let row = ReadStreamIterator::read_row(
            &mut reader,
            row_pos..row_end,
            self.data_length_prefix,
        )?;

        // Prepare position for next iteration
        self.forward = Some(row_end);

        Ok(row)
    }

    /// Attempt to read the next log row for backward iteration.
    fn read_row_next_back(&mut self) -> Result<T> {
        let row_pos = self.backward.unwrap();

        let mut reader =
            BinaryReader::new(&mut *self.read_stream, Endian::Big);

        // Read in the reverse iteration row length
        reader.seek(row_pos - 4)?;
        let row_len = reader.read_u32()?;

        // Position of the beginning of the row
        let row_start = row_pos - (row_len as usize + 8);
        let row_end = row_start + (row_len as usize + 8);

        // Seek to the beginning of the row after the initial
        // row length so we can read in the row data
        reader.seek(row_start + 4)?;
        let row = ReadStreamIterator::read_row(
            &mut reader,
            row_start..row_end,
            self.data_length_prefix,
        )?;

        // Prepare position for next iteration.
        self.backward = Some(row_start);

        Ok(row)
    }
}

impl<T: FileItem> Iterator for ReadStreamIterator<T> {
    type Item = Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let offset: usize = self.header_offset;

        if let (Some(lpos), Some(rpos)) = (self.forward, self.backward) {
            if lpos == rpos {
                return None;
            }
        }

        match self.read_stream.len() {
            Ok(len) => {
                if len > offset {
                    // Got to EOF
                    if let Some(lpos) = self.forward {
                        if lpos == len {
                            return None;
                        }
                    }

                    if self.forward.is_none() {
                        self.forward = Some(offset);
                    }

                    Some(self.read_row_next())
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}

impl<T: FileItem> DoubleEndedIterator for ReadStreamIterator<T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let offset: usize = self.header_offset;

        if let (Some(lpos), Some(rpos)) = (self.forward, self.backward) {
            if lpos == rpos {
                return None;
            }
        }

        match self.read_stream.len() {
            Ok(len) => {
                if len > 4 {
                    // Got to EOF
                    if let Some(rpos) = self.backward {
                        if rpos == offset {
                            return None;
                        }
                    }

                    if self.backward.is_none() {
                        self.backward = Some(len);
                    }
                    Some(self.read_row_next_back())
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}
