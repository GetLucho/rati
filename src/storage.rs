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
    S3 {
        client: aws_sdk_s3::Client,
        bucket: Box<str>,
        key: Box<str>,
        /// ETag the index was built against; every read is pinned to it.
        etag: Box<str>,
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
        if let Some((bucket, key)) = parse_s3_url(source) {
            return open_s3(bucket, key).await;
        }

        open_local(source)
    }

    /// Read `length` bytes at `offset`. The only place where the backends diverge.
    pub async fn read_range(&self, offset: u64, length: u64) -> Result<Bytes, Error> {
        if length == 0 {
            return Ok(Bytes::new());
        }

        let data = match self {
            Self::S3 {
                client,
                bucket,
                key,
                etag,
            } => read_s3_range(client, bucket, key, etag, offset, length).await,
            Self::Local { file } => read_local_range(file.clone(), offset, length).await,
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

/// Open the archive from the local filesystem. ETag is synthesized from `mtime+size`
/// (matches a fresh value whenever the archive changes); Last-Modified is the file's
/// mtime formatted as an HTTP-date.
fn open_local(path: &str) -> Result<(Storage, ArchiveSource), Error> {
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
    let file =
        std::fs::File::open(path).map_err(|e| Error::Io(format!("open({path}) failed: {e}")))?;

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

async fn read_local_range(
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

/// S3-backed tar archive: `HeadObject` for metadata, ranged `GetObject` for reads.
/// Split an `s3://bucket/key` URL into its bucket and key.
fn parse_s3_url(url: &str) -> Option<(&str, &str)> {
    let path = url.strip_prefix("s3://")?;
    path.split_once('/')
}

/// Open the archive from S3: HeadObject for ETag/Last-Modified/size, then hand back the
/// pieces `Archive::open` needs to read the rest.
async fn open_s3(bucket: &str, key: &str) -> Result<(Storage, ArchiveSource), Error> {
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
            etag: etag.clone(),
        },
        ArchiveSource {
            etag,
            last_modified,
            size,
        },
    ))
}

/// The `GetObject` request for one ranged read, pinned to `etag`.
fn ranged_read(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    etag: &str,
    offset: u64,
    length: u64,
) -> aws_sdk_s3::operation::get_object::builders::GetObjectFluentBuilder {
    client
        .get_object()
        .bucket(bucket)
        .key(key)
        .range(format!("bytes={}-{}", offset, offset + length - 1))
        .if_match(etag)
}

/// Read `length` bytes at `offset` from the object.
///
/// Every read is conditional on the ETag captured when the archive was opened. The tile
/// index maps ids to byte offsets in one specific version of the object, so if the archive
/// is replaced while rati is running those offsets now point into different data. Without
/// the guard S3 happily returns whatever occupies that range, and rati serves it under the
/// old ETag and `Cache-Control: immutable` — silently poisoning client and CDN caches.
/// With it, S3 answers 412 and the read fails visibly.
async fn read_s3_range(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    etag: &str,
    offset: u64,
    length: u64,
) -> Result<Bytes, Error> {
    let resp = ranged_read(client, bucket, key, etag, offset, length)
        .send()
        .await
        .map_err(|e| {
            Error::Io(format!(
                "S3 GetObject failed: {e} (a 412 here means the archive was replaced \
                 while rati was running; restart it)"
            ))
        })?;
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

    /// The exact-length contract every caller relies on: `scan_tar_headers` computes
    /// `chunk.len() - local`, which underflows on a short read.
    #[tokio::test]
    async fn a_short_read_is_rejected() {
        let dir = std::env::temp_dir().join(format!("rati-short-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiny.tar");
        std::fs::write(&path, b"0123456789").unwrap();

        let (storage, _) = Storage::open(path.to_str().unwrap()).await.unwrap();

        // Fully satisfiable reads are returned verbatim.
        assert_eq!(storage.read_range(0, 4).await.unwrap().as_ref(), b"0123");
        // A zero-length read never reaches a backend.
        assert!(storage.read_range(4, 0).await.unwrap().is_empty());

        // Asking past the end must fail loudly rather than hand back a short buffer.
        let err = storage.read_range(6, 8).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("offset=6"), "unexpected error: {msg}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every ranged read must be pinned to the ETag captured at open. Without it an
    /// object replaced mid-flight is served at stale offsets under the old ETag and
    /// `Cache-Control: immutable`, poisoning client and CDN caches.
    #[test]
    fn every_ranged_read_is_pinned_to_the_etag() {
        let client = aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::Config::builder()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "id", "secret", None, None, "test",
                ))
                .build(),
        );

        let req = ranged_read(
            &client,
            "bucket",
            "planet.tar",
            "\"abc123\"",
            1536,
            44_504_000,
        );
        assert_eq!(
            req.get_if_match().as_deref(),
            Some("\"abc123\""),
            "ranged reads must carry If-Match"
        );
        assert_eq!(req.get_range().as_deref(), Some("bytes=1536-44505535"));
    }

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
