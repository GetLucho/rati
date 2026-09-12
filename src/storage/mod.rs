//! Storage backends for a tar archive. Hides whether bytes come from S3 or a local file —
//! every read goes through [`Storage::read_range`]; everything above this layer is unaware
//! of the source.

mod local;
mod s3;

use std::sync::Arc;

use bytes::Bytes;

use crate::archive::Error;

/// Source metadata read once when the archive is opened.
pub struct ArchiveSource {
    /// Source ETag — S3 object ETag, or synthesized `"<mtime>-<size>"` for local archives.
    pub etag: Box<str>,
    /// Source Last-Modified as an HTTP-date string.
    pub last_modified: Box<str>,
    /// Total size of the archive in bytes.
    pub size: u64,
}

pub enum Storage {
    S3 {
        client: aws_sdk_s3::Client,
        bucket: Box<str>,
        key: Box<str>,
    },
    Local {
        // `Arc<std::fs::File>` lets us call `read_at` (which takes `&self`) concurrently
        // from multiple `spawn_blocking` tasks without `try_clone()` syscalls per read.
        file: Arc<std::fs::File>,
    },
}

impl Storage {
    /// Open `source`: an S3 URL (`s3://bucket/key`) or a local filesystem path.
    pub async fn open(source: &str) -> Result<(Self, ArchiveSource), Error> {
        if let Some((bucket, key)) = s3::parse_s3_url(source) {
            s3::open_s3(bucket, key).await
        } else {
            local::open_local(source)
        }
    }

    /// Read `length` bytes at `offset`. The only place where the backends diverge.
    pub async fn read_range(&self, offset: u64, length: u64) -> Result<Bytes, Error> {
        if length == 0 {
            return Ok(Bytes::new());
        }

        match self {
            Self::S3 {
                client,
                bucket,
                key,
            } => s3::read_s3_range(client, bucket, key, offset, length).await,
            Self::Local { file } => local::read_local_range(file.clone(), offset, length).await,
        }
    }
}
