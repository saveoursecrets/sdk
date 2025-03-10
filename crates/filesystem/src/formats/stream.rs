//! File streams.
use crate::{formats::FileItem, Result};
use async_trait::async_trait;
use binary_stream::futures::{stream_length, BinaryReader};
use sos_core::encoding::encoding_options;
use sos_vfs::File;
use std::{io::SeekFrom, ops::Range};
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt};

/// Trait for file format iterators.
#[async_trait]
pub trait FormatStreamIterator<T>
where
    T: FileItem + Send,
{
    /// Next entry in the iterator.
    async fn next(&mut self) -> Result<Option<T>>;
}

/// Generic iterator for file formats.
///
/// Supports files and in-memory buffers and can iterate lazily
/// in both directions.
pub struct FormatStream<T, R>
where
    T: FileItem + Send,
    R: AsyncRead + AsyncSeek + Unpin + Send,
{
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
    read_stream: R,
    /// Byte offset for forward iteration.
    forward: Option<u64>,
    /// Byte offset for backward iteration.
    backward: Option<u64>,
    /// Whether to iterate in reverse.
    reverse: bool,
    /// Marker type.
    marker: std::marker::PhantomData<T>,
}

impl<T: FileItem + Send> FormatStream<T, File> {
    /// Create a new file iterator.
    pub async fn new_file(
        mut read_stream: File,
        identity: &'static [u8],
        data_length_prefix: bool,
        header_offset: Option<u64>,
        reverse: bool,
    ) -> Result<Self> {
        let header_offset = header_offset.unwrap_or(identity.len() as u64);
        read_stream.seek(SeekFrom::Start(header_offset)).await?;

        Ok(Self {
            header_offset,
            data_length_prefix,
            read_stream,
            forward: None,
            backward: None,
            reverse,
            marker: std::marker::PhantomData,
        })
    }
}

#[async_trait]
impl<T: FileItem + Send> FormatStreamIterator<T> for FormatStream<T, File> {
    async fn next(&mut self) -> Result<Option<T>> {
        if self.reverse {
            self.next_back().await
        } else {
            self.next_forward().await
        }
    }
}

/*
#[async_trait]
impl<T: FileItem + Send> FormatStreamIterator<T>
    for FormatStream<T, MemoryBuffer>
{
    async fn next(&mut self) -> Result<Option<T>> {
        if self.reverse {
            self.next_back().await
        } else {
            self.next_forward().await
        }
    }
}
*/

impl<T, R> FormatStream<T, R>
where
    T: FileItem + Send,
    R: AsyncRead + AsyncSeek + Unpin + Send,
{
    /// Set the byte offset that constrains iteration.
    ///
    /// Useful when creating streams of log events.
    pub fn set_offset(&mut self, offset: u64) {
        self.header_offset = offset;
    }

    /// Helper to decode the row file record.
    async fn read_row(
        reader: &mut BinaryReader<&mut R>,
        offset: Range<u64>,
        is_prefix: bool,
    ) -> Result<T> {
        let mut row: T = Default::default();

        row.decode(&mut *reader).await?;

        if is_prefix {
            // The byte range for the row value.
            let value_len = reader.read_u32().await?;

            let begin = reader.stream_position().await?;
            let end = begin + value_len as u64;
            row.set_value(begin..end);
        } else {
            row.set_value(offset.start + 4..offset.end - 4);
        }

        row.set_offset(offset);
        Ok(row)
    }

    /// Attempt to read the next log row.
    async fn read_row_next(&mut self) -> Result<T> {
        let row_pos = self.forward.unwrap();

        let mut reader =
            BinaryReader::new(&mut self.read_stream, encoding_options());
        reader.seek(SeekFrom::Start(row_pos)).await?;
        let row_len = reader.read_u32().await?;

        // Position of the end of the row
        let row_end = row_pos + (row_len as u64 + 8);

        let row = FormatStream::read_row(
            &mut reader,
            row_pos..row_end,
            self.data_length_prefix,
        )
        .await?;

        // Prepare position for next iteration
        self.forward = Some(row_end);

        Ok(row)
    }

    /// Attempt to read the next log row for backward iteration.
    async fn read_row_next_back(&mut self) -> Result<T> {
        let row_pos = self.backward.unwrap();

        let mut reader =
            BinaryReader::new(&mut self.read_stream, encoding_options());

        // Read in the reverse iteration row length
        reader.seek(SeekFrom::Start(row_pos - 4)).await?;
        let row_len = reader.read_u32().await?;

        // Position of the beginning of the row
        // FIXME: handle panic on overflow when file length is too short
        let row_start = row_pos - (row_len as u64 + 8);
        let row_end = row_start + (row_len as u64 + 8);

        // Seek to the beginning of the row after the initial
        // row length so we can read in the row data
        reader.seek(SeekFrom::Start(row_start + 4)).await?;
        let row = FormatStream::read_row(
            &mut reader,
            row_start..row_end,
            self.data_length_prefix,
        )
        .await?;

        // Prepare position for next iteration.
        self.backward = Some(row_start);

        Ok(row)
    }

    async fn next_forward(&mut self) -> Result<Option<T>> {
        let offset = self.header_offset;

        if let (Some(lpos), Some(rpos)) = (self.forward, self.backward) {
            if lpos == rpos {
                return Ok(None);
            }
        }

        let len = stream_length(&mut self.read_stream).await?;
        if len > offset {
            // Got to EOF
            if let Some(lpos) = self.forward {
                if lpos == len {
                    return Ok(None);
                }
            }

            if self.forward.is_none() {
                self.forward = Some(offset);
            }

            Ok(Some(self.read_row_next().await?))
        } else {
            Ok(None)
        }
    }

    async fn next_back(&mut self) -> Result<Option<T>> {
        let offset: u64 = self.header_offset;

        if let (Some(lpos), Some(rpos)) = (self.forward, self.backward) {
            if lpos == rpos {
                return Ok(None);
            }
        }

        let len = stream_length(&mut self.read_stream).await?;
        if len > offset {
            // Got to EOF
            if let Some(rpos) = self.backward {
                if rpos == offset {
                    return Ok(None);
                }
            }

            if self.backward.is_none() {
                self.backward = Some(len);
            }
            Ok(Some(self.read_row_next_back().await?))
        } else {
            Ok(None)
        }
    }
}
