//! Storage backends for a tar archive. Hides whether bytes come from S3, Azure Blob,
//! or a local file —
//! every read goes through [`Storage::read_range`]; everything above this layer is unaware
//! of the source.

#[cfg(feature = "azure")]
mod azure;

#[cfg(feature = "azure")]
pub use azure::{CredentialKind, UserAssignedIdKind};
mod local;
#[cfg(feature = "s3")]
mod s3;

use std::sync::Arc;

use bytes::Bytes;

use crate::archive::Error;

/// Azure-specific knobs, threaded through from the command line. Inert for the
/// other backends, and for every backend when the `azure` feature is off.
#[derive(Debug, Default, Clone, Copy)]
pub struct AzureOptions<'a> {
    /// Id of a user-assigned managed identity, and which kind of id it is.
    #[cfg(feature = "azure")]
    pub user_assigned: Option<(&'a str, azure::UserAssignedIdKind)>,
    /// Azure Pipelines service connection id.
    #[cfg(feature = "azure")]
    pub service_connection_id: Option<&'a str>,
    /// Force a credential instead of detecting one from the environment.
    #[cfg(feature = "azure")]
    pub credential: Option<azure::CredentialKind>,
    #[cfg(not(feature = "azure"))]
    pub _unused: std::marker::PhantomData<&'a ()>,
}

/// Strip the query string from an archive location before it is logged or put in an
/// error.
///
/// An Azure Blob URL may carry a shared access signature there — `?...&sig=...` — which
/// is a bearer credential. Anything that prints the archive location must go through
/// this, or the token lands in stdout and every log aggregator downstream.
pub fn redact(source: &str) -> &str {
    match source.split_once('?') {
        Some((head, _)) => head,
        None => source,
    }
}

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
    #[cfg(feature = "azure")]
    AzureBlob {
        client: Box<azure_storage_blob::BlobClient>,
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
    pub async fn open(
        source: &str,
        #[allow(unused_variables)] opts: AzureOptions<'_>,
    ) -> Result<(Self, ArchiveSource), Error> {
        #[cfg(feature = "azure")]
        if azure::is_azure_url(source) {
            return azure::open_azure(
                source,
                opts.user_assigned,
                opts.service_connection_id,
                opts.credential,
            )
            .await;
        }

        #[cfg(feature = "azure")]
        if source.starts_with("https://") || source.starts_with("http://") {
            return Err(Error::Protocol(format!(
                "{source} is not an Azure Blob endpoint; expected \
                 https://<account>.blob.core.windows.net/<container>/<blob>.tar"
            )));
        }
        #[cfg(not(feature = "azure"))]
        if source.starts_with("https://") || source.starts_with("http://") {
            return Err(Error::Protocol(
                "HTTP(S) archives require the 'azure' cargo feature".into(),
            ));
        }

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

        match self {
            #[cfg(feature = "s3")]
            Self::S3 {
                client,
                bucket,
                key,
            } => s3::read_s3_range(client, bucket, key, offset, length).await,
            #[cfg(feature = "azure")]
            Self::AzureBlob { client, etag } => {
                azure::read_azure_range(client, etag, offset, length).await
            }
            Self::Local { file } => local::read_local_range(file.clone(), offset, length).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_strips_the_query_string() {
        // A SAS is a bearer credential and must never reach a log or an error.
        assert_eq!(
            redact("https://acct.blob.core.windows.net/t/p.tar?sv=2024-11-04&sig=SECRET"),
            "https://acct.blob.core.windows.net/t/p.tar"
        );
        // Nothing to strip: left exactly as-is, including for the other backends.
        assert_eq!(
            redact("https://acct.blob.core.windows.net/t/p.tar"),
            "https://acct.blob.core.windows.net/t/p.tar"
        );
        assert_eq!(redact("s3://bucket/planet.tar"), "s3://bucket/planet.tar");
        assert_eq!(redact("/data/planet.tar"), "/data/planet.tar");
        // A bare "?" still loses everything after it.
        assert_eq!(redact("https://h/p.tar?"), "https://h/p.tar");
    }
}
