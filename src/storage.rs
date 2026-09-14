//! Storage backends for a tar archive. Hides whether bytes come from S3 or a local
//! file — every read goes through [`Storage::read_range`]; everything above this layer
//! is unaware of the source.

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
    #[cfg(feature = "s3")]
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
        #[cfg(feature = "s3")]
        if let Some((bucket, key)) = s3::parse_s3_url(source) {
            return s3::open_s3(bucket, key).await;
        }

        #[cfg(not(feature = "s3"))]
        if source.starts_with("s3://") {
            return Err(Error::Protocol(
                "S3 archives require the 's3' cargo feature".into(),
            ));
        }

        local::open_local(source)
    }

    /// Read `length` bytes at `offset`. The only place where the backends diverge.
    pub async fn read_range(&self, offset: u64, length: u64) -> Result<Bytes, Error> {
        if length == 0 {
            return Ok(Bytes::new());
        }

        let data = match self {
            #[cfg(feature = "s3")]
            Self::S3 {
                client,
                bucket,
                key,
            } => s3::read_s3_range(client, bucket, key, offset, length).await,
            Self::Local { file } => local::read_local_range(file.clone(), offset, length).await,
        }?;

        // Callers index into the result assuming it is exactly `length` bytes;
        // `scan_tar_headers` subtracts from `chunk.len()` and would underflow on a short
        // read. A ranged GET may return less, so enforce it here once for every backend.
        if data.len() as u64 != length {
            return Err(Error::Io(format!(
                "short read at offset={offset}: asked for {length} bytes, got {}",
                data.len()
            )));
        }
        Ok(data)
    }
}

/// Filesystem-backed tar archive: `stat` for metadata, positional reads for ranges.
mod local {
    use std::sync::Arc;

    use bytes::Bytes;

    use super::{ArchiveSource, Storage};
    use crate::archive::Error;

    /// Open the archive from the local filesystem. ETag is synthesized from `mtime+size`
    /// (matches a fresh value whenever the archive changes); Last-Modified is the file's
    /// mtime formatted as an HTTP-date.
    pub(super) fn open_local(path: &str) -> Result<(Storage, ArchiveSource), Error> {
        let metadata =
            std::fs::metadata(path).map_err(|e| Error::Io(format!("stat({path}) failed: {e}")))?;
        if !metadata.is_file() {
            return Err(Error::Protocol(format!("{path} is not a regular file")));
        }
        let size = metadata.len();
        let mtime = metadata
            .modified()
            .map_err(|e| Error::Io(format!("{path} has no mtime: {e}")))?;
        let mtime_unix = mtime
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Protocol("file mtime is before UNIX epoch".into()))?
            .as_secs();
        let etag: Box<str> = format!("\"{mtime_unix}-{size}\"").into();
        let last_modified: Box<str> = httpdate::fmt_http_date(mtime).into();
        let file = std::fs::File::open(path)
            .map_err(|e| Error::Io(format!("open({path}) failed: {e}")))?;

        Ok((
            Storage::Local {
                file: Arc::new(file),
            },
            ArchiveSource {
                etag,
                last_modified,
                size,
            },
        ))
    }

    pub(super) async fn read_local_range(
        file: Arc<std::fs::File>,
        offset: u64,
        length: u64,
    ) -> Result<Bytes, Error> {
        let len = length as usize;
        tokio::task::spawn_blocking(move || {
            use std::os::unix::fs::FileExt;
            let mut buf = vec![0u8; len];
            file.read_exact_at(&mut buf, offset)
                .map(|()| Bytes::from(buf))
        })
        .await
        .map_err(|e| Error::Io(format!("local read task panicked: {e}")))?
        .map_err(|e| {
            Error::Io(format!(
                "local read_at(offset={offset}, len={length}) failed: {e}"
            ))
        })
    }
}

/// S3-backed tar archive: `HeadObject` for metadata, ranged `GetObject` for reads.
#[cfg(feature = "s3")]
mod s3 {
    use bytes::Bytes;

    use super::{ArchiveSource, Storage};
    use crate::archive::Error;

    /// Split an `s3://bucket/key` URL into its bucket and key.
    pub(super) fn parse_s3_url(url: &str) -> Option<(&str, &str)> {
        let path = url.strip_prefix("s3://")?;
        path.split_once('/')
    }

    /// Open the archive from S3: HeadObject for ETag/Last-Modified/size, then hand back the
    /// pieces `Archive::open` needs to read the rest.
    pub(super) async fn open_s3(
        bucket: &str,
        key: &str,
    ) -> Result<(Storage, ArchiveSource), Error> {
        let client = aws_sdk_s3::Client::new(
            &aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await,
        );

        let head = client
            .head_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| Error::Io(format!("HeadObject failed: {e}")))?;

        let etag: Box<str> = head
            .e_tag()
            .ok_or_else(|| Error::Protocol("S3 HeadObject returned no ETag".into()))?
            .into();

        let last_modified: Box<str> = head
            .last_modified()
            .and_then(|dt| {
                dt.fmt(aws_sdk_s3::primitives::DateTimeFormat::HttpDate)
                    .ok()
            })
            .ok_or_else(|| Error::Protocol("S3 HeadObject returned no Last-Modified".into()))?
            .into();

        let size = head
            .content_length()
            .ok_or_else(|| Error::Protocol("S3 HeadObject returned no Content-Length".into()))?
            as u64;

        Ok((
            Storage::S3 {
                client,
                bucket: bucket.into(),
                key: key.into(),
            },
            ArchiveSource {
                etag,
                last_modified,
                size,
            },
        ))
    }

    pub(super) async fn read_s3_range(
        client: &aws_sdk_s3::Client,
        bucket: &str,
        key: &str,
        offset: u64,
        length: u64,
    ) -> Result<Bytes, Error> {
        let range = format!("bytes={}-{}", offset, offset + length - 1);
        let resp = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .range(&range)
            .send()
            .await
            .map_err(|e| Error::Io(format!("S3 GetObject failed: {e}")))?;
        let data = resp
            .body
            .collect()
            .await
            .map_err(|e| Error::Io(format!("reading S3 response body: {e}")))?
            .into_bytes();

        Ok(data)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_s3_url_test() {
            assert_eq!(
                parse_s3_url("s3://my-bucket/path/to/file.tar"),
                Some(("my-bucket", "path/to/file.tar"))
            );
            assert_eq!(
                parse_s3_url("s3://bucket/file.tar"),
                Some(("bucket", "file.tar"))
            );

            assert_eq!(parse_s3_url("bucket/key"), None);
            assert_eq!(parse_s3_url("https://wrong/scheme"), None);
            assert_eq!(parse_s3_url("s3:/bad-url/format"), None);
            assert_eq!(parse_s3_url("s3://bucket-only"), None);
            assert_eq!(parse_s3_url("s3://file-only.tar"), None);
        }
    }
}
