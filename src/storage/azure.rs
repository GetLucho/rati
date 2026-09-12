//! Azure Blob Storage backend: byte-range reads against a blob holding the tar archive.

use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_core::http::Url;
use azure_core::http::headers::HeaderName;
use azure_identity::{
    DeveloperToolsCredential, ManagedIdentityCredential, ManagedIdentityCredentialOptions,
    UserAssignedId,
};
use azure_storage_blob::BlobClient;
use azure_storage_blob::models::{BlobClientDownloadOptions, HttpRange};
use bytes::Bytes;

use super::{ArchiveSource, Storage};
use crate::archive::Error;

/// Bytes read to probe the archive: one tar header block.
const PROBE_LEN: u64 = 512;

/// The SDK keeps its own `ContentRange` type private, so read the header directly.
const CONTENT_RANGE: HeaderName = HeaderName::from_static("content-range");

/// Host suffixes that identify an Azure Blob endpoint, across public and sovereign clouds.
const BLOB_HOST_SUFFIXES: [&str; 4] = [
    ".blob.core.windows.net",
    ".blob.core.usgovcloudapi.net",
    ".blob.core.chinacloudapi.cn",
    ".blob.core.cloudapi.de",
];

/// True when `source` is an HTTPS URL pointing at an Azure Blob endpoint.
pub(super) fn is_azure_url(source: &str) -> bool {
    let Some(rest) = source.strip_prefix("https://") else {
        return false;
    };
    let host = rest
        .split(['/', '?'])
        .next()
        .unwrap_or_default()
        .split('@')
        .next_back()
        .unwrap_or_default();
    BLOB_HOST_SUFFIXES
        .iter()
        .any(|suffix| host.len() > suffix.len() && host.ends_with(suffix))
}

/// True when the URL carries a shared access signature, meaning no credential is needed.
pub(super) fn has_sas_token(url: &str) -> bool {
    let Some((_, query)) = url.split_once('?') else {
        return false;
    };
    query
        .split('&')
        .any(|param| param.split_once('=').is_some_and(|(k, _)| k == "sig"))
}

/// Which credential rati should present to Azure Blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CredentialKind {
    /// The URL carries a SAS; no credential needed.
    Anonymous,
    /// Running on Azure — Container Apps, App Service, or a VM.
    ManagedIdentity,
    /// Local development; chains the az and azd CLIs.
    DeveloperTools,
}

/// Pick a credential from the URL and the ambient environment.
///
/// Azure Container Apps injects `IDENTITY_ENDPOINT` (with `IDENTITY_HEADER`) for
/// both system- and user-assigned identities, which is what `azure_identity`'s
/// App Service source reads.
pub(super) fn select_credential_kind(url: &str, identity_endpoint: Option<&str>) -> CredentialKind {
    if has_sas_token(url) {
        CredentialKind::Anonymous
    } else if identity_endpoint.is_some_and(|e| !e.is_empty()) {
        CredentialKind::ManagedIdentity
    } else {
        CredentialKind::DeveloperTools
    }
}

/// Extract the total resource length from a `Content-Range` header value.
///
/// Per RFC 9110 §14.4 the value is `bytes <range>/<complete-length>`, where the
/// complete length is `*` when the server does not know it.
pub(super) fn parse_content_range_total(header: &str) -> Option<u64> {
    header
        .strip_prefix("bytes ")?
        .rsplit_once('/')
        .map(|(_, total)| total)?
        .trim()
        .parse()
        .ok()
}

/// Build the credential rati presents to Azure Blob for `url`.
fn build_credential(
    url: &str,
    user_assigned_id: Option<&str>,
) -> Result<Option<Arc<dyn TokenCredential>>, Error> {
    let identity_endpoint = std::env::var("IDENTITY_ENDPOINT").ok();
    match select_credential_kind(url, identity_endpoint.as_deref()) {
        CredentialKind::Anonymous => Ok(None),
        CredentialKind::ManagedIdentity => {
            let options = user_assigned_id.map(|id| ManagedIdentityCredentialOptions {
                user_assigned_id: Some(UserAssignedId::ClientId(id.to_string())),
                ..Default::default()
            });
            let credential = ManagedIdentityCredential::new(options)
                .map_err(|e| Error::Io(format!("managed identity credential: {e}")))?;
            Ok(Some(credential))
        }
        CredentialKind::DeveloperTools => {
            let credential = DeveloperToolsCredential::new(None)
                .map_err(|e| Error::Io(format!("developer tools credential: {e}")))?;
            Ok(Some(credential))
        }
    }
}

/// Open the archive from Azure Blob Storage.
///
/// Reads the leading tar block to pick up the blob's ETag, Last-Modified, and total
/// size in one request: `get_properties` returns its values as raw headers, whereas a
/// ranged `download` hands back a typed `BlobDownloadProperties`.
pub(super) async fn open_azure(
    url: &str,
    user_assigned_id: Option<&str>,
) -> Result<(Storage, ArchiveSource), Error> {
    let parsed =
        Url::parse(url).map_err(|e| Error::Protocol(format!("invalid blob URL {url}: {e}")))?;
    let credential = build_credential(url, user_assigned_id)?;

    let client = BlobClient::new(parsed, credential, None)
        .map_err(|e| Error::Io(format!("creating blob client: {e}")))?;

    let probe = client
        .download(Some(BlobClientDownloadOptions {
            range: Some(HttpRange::new(0, PROBE_LEN)),
            ..Default::default()
        }))
        .await
        .map_err(|e| Error::Io(format!("blob metadata probe failed: {e}")))?;

    let etag: Box<str> = probe
        .properties
        .etag
        .as_ref()
        .map(ToString::to_string)
        .ok_or_else(|| Error::Protocol("blob response carried no ETag".into()))?
        .into();

    let last_modified: Box<str> = probe
        .properties
        .last_modified
        .map(|t| httpdate::fmt_http_date(t.into()))
        .ok_or_else(|| Error::Protocol("blob response carried no Last-Modified".into()))?
        .into();

    let size = probe
        .headers
        .get_optional_str(&CONTENT_RANGE)
        .and_then(parse_content_range_total)
        .ok_or_else(|| Error::Protocol("blob response carried no usable Content-Range".into()))?;

    Ok((
        Storage::AzureBlob {
            client: Box::new(client),
        },
        ArchiveSource {
            etag,
            last_modified,
            size,
        },
    ))
}

/// Read `length` bytes at `offset` from the blob.
pub(super) async fn read_azure_range(
    client: &BlobClient,
    offset: u64,
    length: u64,
) -> Result<Bytes, Error> {
    let response = client
        .download(Some(BlobClientDownloadOptions {
            range: Some(HttpRange::new(offset, length)),
            ..Default::default()
        }))
        .await
        .map_err(|e| Error::Io(format!("blob download(offset={offset}, len={length}): {e}")))?;

    response
        .body
        .collect()
        .await
        .map_err(|e| Error::Io(format!("reading blob response body: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_azure_url_test() {
        assert!(is_azure_url(
            "https://acct.blob.core.windows.net/tiles/planet.tar"
        ));
        assert!(is_azure_url(
            "https://acct.blob.core.usgovcloudapi.net/tiles/planet.tar"
        ));
        assert!(is_azure_url(
            "https://acct.blob.core.windows.net/tiles/planet.tar?sv=2024-11-04&sig=abc"
        ));

        assert!(!is_azure_url("s3://bucket/planet.tar"));
        assert!(!is_azure_url("./planet.tar"));
        assert!(!is_azure_url("/data/planet.tar"));
        // https, but not a blob endpoint
        assert!(!is_azure_url("https://example.com/planet.tar"));
        // the suffix alone, with no account label, is not a blob URL
        assert!(!is_azure_url("https://blob.core.windows.net/tiles/p.tar"));
    }

    #[test]
    fn has_sas_token_test() {
        assert!(has_sas_token(
            "https://acct.blob.core.windows.net/t/p.tar?sv=2024-11-04&sig=abc%3D"
        ));
        assert!(has_sas_token(
            "https://acct.blob.core.windows.net/t/p.tar?sp=r&st=2026-01-01&sig=x"
        ));

        assert!(!has_sas_token("https://acct.blob.core.windows.net/t/p.tar"));
        // a query string without a signature is not a SAS
        assert!(!has_sas_token(
            "https://acct.blob.core.windows.net/t/p.tar?snapshot=2026-01-01"
        ));
        // a parameter merely ending in "sig" must not match
        assert!(!has_sas_token(
            "https://acct.blob.core.windows.net/t/p.tar?nosig=x"
        ));
    }

    #[test]
    fn select_credential_kind_test() {
        use CredentialKind::*;

        let plain = "https://acct.blob.core.windows.net/t/p.tar";
        let sas = "https://acct.blob.core.windows.net/t/p.tar?sv=1&sig=abc";

        // A SAS in the URL authenticates the request on its own.
        assert_eq!(select_credential_kind(sas, None), Anonymous);
        assert_eq!(
            select_credential_kind(sas, Some("http://169.254.0.1/token")),
            Anonymous
        );

        // Container Apps injects IDENTITY_ENDPOINT.
        assert_eq!(
            select_credential_kind(plain, Some("http://169.254.0.1/token")),
            ManagedIdentity
        );

        // Local development falls back to the az CLI.
        assert_eq!(select_credential_kind(plain, None), DeveloperTools);
        assert_eq!(select_credential_kind(plain, Some("")), DeveloperTools);
    }

    #[test]
    fn parse_content_range_total_test() {
        assert_eq!(
            parse_content_range_total("bytes 0-511/85899345920"),
            Some(85_899_345_920)
        );
        assert_eq!(parse_content_range_total("bytes 0-0/1"), Some(1));

        // unsatisfiable / unknown total
        assert_eq!(parse_content_range_total("bytes 0-511/*"), None);
        assert_eq!(parse_content_range_total("bytes */1234"), Some(1234));
        assert_eq!(parse_content_range_total("garbage"), None);
        assert_eq!(parse_content_range_total(""), None);
    }
}
