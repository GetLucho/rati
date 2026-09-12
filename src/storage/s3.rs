//! S3-backed tar archive: `HeadObject` for metadata, ranged `GetObject` for reads.

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
pub(super) async fn open_s3(bucket: &str, key: &str) -> Result<(Storage, ArchiveSource), Error> {
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
