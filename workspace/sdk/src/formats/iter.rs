//! File format iterators.
use std::{
    io::{Read, Seek, SeekFrom},
    ops::Range,
};

use binary_stream::{tokio::Decode, BinaryReader, BinaryResult, Endian};

use crate::{
    constants::{
        AUDIT_IDENTITY, EVENT_LOG_IDENTITY, PATCH_IDENTITY, VAULT_IDENTITY,
    },
    encoding::stream_len,
    formats::FileIdentity,
    vault::Header,
    Result, Timestamp,
};

use std::fs::File;

use std::path::Path;

/// Get an iterator for a vault file.
pub fn vault_iter<P: AsRef<Path>>(
    path: P,
) -> Result<ReadStreamIterator<File, VaultRecord>> {
    /*
    let content_offset = Header::read_content_offset(path.as_ref())?;
    ReadStreamIterator::<File, VaultRecord>::new_file(
        path.as_ref(),
        &VAULT_IDENTITY,
        true,
        Some(content_offset),
    )
    */

    todo!();
}

/// Get an iterator for a event log file.
pub fn event_log_iter<P: AsRef<Path>>(
    path: P,
) -> Result<ReadStreamIterator<File, EventLogFileRecord>> {
    /*
    ReadStreamIterator::<File, EventLogFileRecord>::new_file(
        path.as_ref(),
        &EVENT_LOG_IDENTITY,
        true,
        None,
    )
    */

    todo!();
}

/// Get an iterator for a patch file.
pub fn patch_iter<P: AsRef<Path>>(
    path: P,
) -> Result<ReadStreamIterator<File, FileRecord>> {
    todo!();
    //ReadStreamIterator::new_file(path.as_ref(), &PATCH_IDENTITY, false, None)
}

/// Get an iterator for an audit file.
pub fn audit_iter<P: AsRef<Path>>(
    path: P,
) -> Result<ReadStreamIterator<File, FileRecord>> {
    todo!();
    //ReadStreamIterator::new_file(path.as_ref(), &AUDIT_IDENTITY, false, None)
}

/// Trait for types yielded by the file iterator.
pub trait FileItem: Default + std::fmt::Debug + Decode {
    /// Get the byte offset for the record.
    fn offset(&self) -> &Range<u64>;

    /// Get the range for the record value.
    fn value(&self) -> &Range<u64>;

    /// Set the byte offset for the record.
    fn set_offset(&mut self, offset: Range<u64>);

    /// Set the range for the record value.
    fn set_value(&mut self, value: Range<u64>);
}

/// Generic reference to a row in a file.
#[derive(Default, Debug)]
pub struct FileRecord {
    /// Byte offset for the record.
    offset: Range<u64>,
    /// The byte range for the value.
    value: Range<u64>,
}

impl FileItem for FileRecord {
    fn offset(&self) -> &Range<u64> {
        &self.offset
    }

    fn value(&self) -> &Range<u64> {
        &self.value
    }

    fn set_offset(&mut self, offset: Range<u64>) {
        self.offset = offset;
    }

    fn set_value(&mut self, value: Range<u64>) {
        self.value = value;
    }
}

/// Reference to a row in a vault.
#[derive(Default, Debug)]
pub struct VaultRecord {
    /// Byte offset for the record.
    offset: Range<u64>,
    /// The byte range for the value.
    value: Range<u64>,
    /// The identifier for the secret.
    pub(crate) id: [u8; 16],
    /// The commit hash for the secret.
    pub(crate) commit: [u8; 32],
}

impl FileItem for VaultRecord {
    fn offset(&self) -> &Range<u64> {
        &self.offset
    }

    fn value(&self) -> &Range<u64> {
        &self.value
    }

    fn set_offset(&mut self, offset: Range<u64>) {
        self.offset = offset;
    }

    fn set_value(&mut self, value: Range<u64>) {
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

/// Reference to a row in the write ahead log.
#[derive(Default, Debug, Eq)]
pub struct EventLogFileRecord {
    /// Byte offset for the record.
    offset: Range<u64>,
    /// The byte range for the value.
    value: Range<u64>,
    /// The time the row was created.
    pub(crate) time: Timestamp,
    /// The commit hash for the previous row.
    pub(crate) last_commit: [u8; 32],
    /// The commit hash for the value.
    pub(crate) commit: [u8; 32],
}

impl EventLogFileRecord {
    /// Commit hash for this row.
    pub fn commit(&self) -> [u8; 32] {
        self.commit
    }

    /// Commit hash for the previous row.
    pub fn last_commit(&self) -> [u8; 32] {
        self.last_commit
    }

    /// Time the row was appended.
    pub fn time(&self) -> &Timestamp {
        &self.time
    }
}

impl PartialEq for EventLogFileRecord {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
            && self.commit == other.commit
            && self.last_commit == other.last_commit
    }
}

impl FileItem for EventLogFileRecord {
    fn offset(&self) -> &Range<u64> {
        &self.offset
    }

    fn value(&self) -> &Range<u64> {
        &self.value
    }

    fn set_offset(&mut self, offset: Range<u64>) {
        self.offset = offset;
    }

    fn set_value(&mut self, value: Range<u64>) {
        self.value = value;
    }
}

/// Generic iterator for files.
pub struct ReadStreamIterator<R: Read + Seek, T: FileItem> {
    /// Offset from the beginning of the stream where
    /// iteration should start and reverse iteration
    /// should complete.
    ///
    /// This is often the length of the identity magic
    /// bytes but in some cases may be specified when
    /// creating the iterator, for example, vault files
    /// have information in the file header so we need
    /// to pass the offset where the content starts.
    header_offset: u64,

    /// After decoding the row record is there a u32
    /// that is used to indicate the length of a a data
    /// blob for the row; if so then `value` will point
    /// to the data. This is used for lazy decoding such
    /// as in the case of event log files where we need to read
    /// the commit hash(es) and timestamp most of the time
    /// but sometimes need to read the row data too.
    data_length_prefix: bool,
    /// The read stream.
    read_stream: Box<R>,
    /// Byte offset for forward iteration.
    forward: Option<u64>,
    /// Byte offset for backward iteration.
    backward: Option<u64>,
    /// Marker type.
    marker: std::marker::PhantomData<T>,
}

impl<T: FileItem> ReadStreamIterator<std::fs::File, T> {
    /// Create a new file iterator.
    fn new_file<P: AsRef<Path>>(
        file_path: P,
        identity: &'static [u8],
        data_length_prefix: bool,
        header_offset: Option<u64>,
    ) -> Result<Self> {
        todo!();

        /*
        FileIdentity::read_file(file_path.as_ref(), identity)?;
        let mut read_stream = Box::new(File::open(file_path.as_ref())?);

        let header_offset = header_offset.unwrap_or(identity.len() as u64);
        read_stream.seek(SeekFrom::Start(header_offset))?;

        Ok(Self {
            header_offset,
            data_length_prefix,
            read_stream,
            forward: None,
            backward: None,
            marker: std::marker::PhantomData,
        })
        */
    }
}

impl<R: Read + Seek, T: FileItem> ReadStreamIterator<R, T> {
    /// Set the byte offset that constrains iteration.
    ///
    /// Useful when creating streams of log events.
    pub fn set_offset(&mut self, offset: u64) {
        self.header_offset = offset;
    }

    /// Helper to decode the row file record.
    fn read_row(
        reader: &mut BinaryReader<R>,
        offset: Range<u64>,
        is_prefix: bool,
    ) -> Result<T> {
        /*
        let mut row: T = Default::default();

        row.decode(&mut *reader)?;

        if is_prefix {
            // The byte range for the row value.
            let value_len = reader.read_u32()?;

            let begin = reader.tell()?;
            let end = begin + value_len as u64;
            row.set_value(begin..end);
        } else {
            row.set_value(offset.start + 4..offset.end - 4);
        }

        row.set_offset(offset);
        Ok(row)
        */

        todo!();
    }

    /// Attempt to read the next log row.
    fn read_row_next(&mut self) -> Result<T> {
        let row_pos = self.forward.unwrap();

        let mut reader =
            BinaryReader::new(&mut *self.read_stream, Endian::Little);
        reader.seek(row_pos)?;
        let row_len = reader.read_u32()?;

        // Position of the end of the row
        let row_end = row_pos + (row_len as u64 + 8);

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
            BinaryReader::new(&mut *self.read_stream, Endian::Little);

        // Read in the reverse iteration row length
        reader.seek(row_pos - 4)?;
        let row_len = reader.read_u32()?;

        // Position of the beginning of the row
        let row_start = row_pos - (row_len as u64 + 8);
        let row_end = row_start + (row_len as u64 + 8);

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

impl<R: Read + Seek, T: FileItem> Iterator for ReadStreamIterator<R, T> {
    type Item = Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.header_offset;

        if let (Some(lpos), Some(rpos)) = (self.forward, self.backward) {
            if lpos == rpos {
                return None;
            }
        }

        todo!();

        /*
        match stream_len(&mut self.read_stream) {
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
        */
    }
}

impl<R: Read + Seek, T: FileItem> DoubleEndedIterator
    for ReadStreamIterator<R, T>
{
    fn next_back(&mut self) -> Option<Self::Item> {
        let offset: u64 = self.header_offset;

        if let (Some(lpos), Some(rpos)) = (self.forward, self.backward) {
            if lpos == rpos {
                return None;
            }
        }

        todo!();

        /*
        match stream_len(&mut self.read_stream) {
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
        */
    }
}
