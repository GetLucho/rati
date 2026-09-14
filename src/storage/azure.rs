//! Azure Blob Storage backend: byte-range reads against a blob holding the tar archive.

use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_core::http::Etag;
use azure_core::http::Url;
use azure_core::http::headers::HeaderName;
use azure_identity::{
    ClientSecretCredential, DeveloperToolsCredential, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId, WorkloadIdentityCredential,
};
use azure_storage_blob::BlobClient;
use azure_storage_blob::models::{BlobClientDownloadOptions, HttpRange};
use bytes::Bytes;

use super::{ArchiveSource, CredentialKind, Storage, redact};
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

/// Azurite and the legacy emulator both serve this well-known development account.
const EMULATOR_ACCOUNT: &str = "devstoreaccount1";

/// True when `host` is a real Azure Blob endpoint in one of the known clouds.
///
/// `Url` lowercases the host during parsing; hostnames are case-insensitive.
fn has_blob_host_suffix(host: &str) -> bool {
    BLOB_HOST_SUFFIXES
        .iter()
        .any(|suffix| host.len() > suffix.len() && host.ends_with(suffix))
}

/// True when `source` is an HTTP(S) URL that should be served by this backend.
///
/// The two schemes are recognised differently, and the asymmetry is the security
/// boundary. Over https the *host* must prove it is Azure Blob, because an https URL
/// can be credentialed. Over http the emulator is matched on its account name, which
/// lives in the path and which any host could claim — safe only because a bearer
/// token never goes out over plaintext (see [`select_credential_kind`]). Routing
/// plaintext here at all lets [`open_azure`] reject it deliberately rather than
/// letting it fall through and be `stat()`ed as a local filesystem path.
pub(super) fn is_azure_url(source: &str) -> bool {
    let Ok(url) = Url::parse(source) else {
        return false;
    };
    match url.scheme() {
        "https" => url.host_str().is_some_and(has_blob_host_suffix),
        "http" => {
            url.host_str().is_some_and(has_blob_host_suffix)
                || url
                    .path_segments()
                    .and_then(|mut segments| segments.next())
                    .is_some_and(|account| account == EMULATOR_ACCOUNT)
        }
        _ => false,
    }
}

/// True when the URL carries a shared access signature, meaning no credential is needed.
fn has_sas_token(url: &str) -> bool {
    let Some((_, query)) = url.split_once('?') else {
        return false;
    };
    query
        .split('&')
        .any(|param| param.split_once('=').is_some_and(|(k, _)| k == "sig"))
}

/// The environment markers that identify where rati is running.
///
/// Captured as a struct so the selection below is a pure function and can be
/// tested without mutating process-wide environment state.
#[derive(Debug, Default)]
struct CredentialEnv {
    /// Set by Container Apps, App Service and Azure Arc.
    identity_endpoint: Option<String>,
    /// Set by Cloud Shell and Azure ML.
    msi_endpoint: Option<String>,
    /// Set by the AKS workload-identity webhook.
    federated_token_file: Option<String>,
    /// Service-principal tenant. Required by every service-principal credential.
    tenant_id: Option<String>,
    /// Service-principal application id.
    client_id: Option<String>,
    /// Service-principal secret.
    client_secret: Option<String>,
}

impl CredentialEnv {
    /// Read the markers from the process environment.
    fn from_process() -> Self {
        let var = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
        Self {
            identity_endpoint: var("IDENTITY_ENDPOINT"),
            msi_endpoint: var("MSI_ENDPOINT"),
            federated_token_file: var("AZURE_FEDERATED_TOKEN_FILE"),
            tenant_id: var("AZURE_TENANT_ID"),
            client_id: var("AZURE_CLIENT_ID"),
            client_secret: var("AZURE_CLIENT_SECRET"),
        }
    }
}

/// Pick a credential from the URL, the ambient environment, and an optional
/// explicit override.
///
/// `azure_identity` 1.0 ships no `DefaultAzureCredential`, so rati selects one
/// explicitly rather than chaining and probing.
///
/// Detection order matters. A federated token file outranks the managed-identity
/// markers because an AKS pod can carry both, and only the projected token works.
/// A plain Azure VM or VMSS exposes *no* marker — IMDS is reachable but invisible —
/// so that case must be requested by name via `override_kind`.
fn select_credential_kind(
    url: &str,
    env: &CredentialEnv,
    override_kind: Option<CredentialKind>,
) -> CredentialKind {
    // A bearer token must never go out over plaintext, so an http endpoint is
    // anonymous whatever the environment or the operator says. The SDK rejects the
    // combination too, but reports it as an opaque client-construction failure.
    let parsed = Url::parse(url).ok();
    let insecure = parsed.as_ref().is_some_and(|u| u.scheme() != "https");

    // Second line of defence: only a host that is demonstrably Azure Blob is ever
    // given a token, whatever routed the URL here.
    let blob_host = parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .is_some_and(has_blob_host_suffix);

    if insecure || !blob_host || has_sas_token(url) {
        return CredentialKind::Anonymous;
    }

    if let Some(kind) = override_kind {
        return kind;
    }

    let set = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.is_empty());

    // Ordering mirrors DefaultAzureCredential in the other Azure SDKs: an
    // explicitly configured identity outranks an ambient one, and the most
    // specific marker wins. A pod can carry several of these at once.
    if set(&env.federated_token_file) {
        CredentialKind::WorkloadIdentity
    } else if set(&env.tenant_id) && set(&env.client_id) && set(&env.client_secret) {
        CredentialKind::ClientSecret
    } else if set(&env.identity_endpoint) || set(&env.msi_endpoint) {
        CredentialKind::ManagedIdentity
    } else {
        CredentialKind::DeveloperTools
    }
}

/// Extract the total resource length from a `Content-Range` header value.
///
/// Per RFC 9110 §14.4 the value is `bytes <range>/<complete-length>`, where the
/// complete length is `*` when the server does not know it.
fn parse_content_range_total(header: &str) -> Option<u64> {
    header
        .strip_prefix("bytes ")?
        .rsplit_once('/')
        .map(|(_, total)| total)?
        .trim()
        .parse()
        .ok()
}

/// Required environment variable, reported by name when absent.
fn require<'a>(
    value: &'a Option<String>,
    name: &str,
    kind: CredentialKind,
) -> Result<&'a str, Error> {
    value
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::Protocol(format!("{kind:?} credential needs {name} to be set")))
}

/// Build the credential rati presents to Azure Blob for `url`.
fn build_credential(
    env: &CredentialEnv,
    kind: CredentialKind,
    user_assigned: Option<&str>,
) -> Result<Option<Arc<dyn TokenCredential>>, Error> {
    match kind {
        CredentialKind::Anonymous => Ok(None),

        CredentialKind::WorkloadIdentity => {
            let credential = WorkloadIdentityCredential::new(None)
                .map_err(|e| Error::Io(format!("workload identity credential: {e}")))?;
            Ok(Some(credential))
        }

        CredentialKind::ClientSecret => {
            let tenant = require(&env.tenant_id, "AZURE_TENANT_ID", kind)?;
            let client = require(&env.client_id, "AZURE_CLIENT_ID", kind)?;
            let secret = require(&env.client_secret, "AZURE_CLIENT_SECRET", kind)?;
            let credential = ClientSecretCredential::new(
                tenant,
                client.to_string(),
                secret.to_string().into(),
                None,
            )
            .map_err(|e| Error::Io(format!("client secret credential: {e}")))?;
            Ok(Some(credential))
        }

        CredentialKind::ManagedIdentity => {
            let options = user_assigned.map(|id| ManagedIdentityCredentialOptions {
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
/// ranged `download` hands back a typed `BlobDownloadProperties`. The block itself is
/// handed back in [`ArchiveSource::prefetch`] so the caller need not read it again.
pub(super) async fn open_azure(
    url: &str,
    user_assigned: Option<&str>,
    override_kind: Option<CredentialKind>,
) -> Result<(Storage, ArchiveSource), Error> {
    let parsed = Url::parse(url)
        .map_err(|e| Error::Protocol(format!("invalid blob URL {}: {e}", redact(url))))?;
    let env = CredentialEnv::from_process();
    let kind = select_credential_kind(url, &env, override_kind);
    tracing::info!("Azure credential: {kind:?}");
    let credential = build_credential(&env, kind, user_assigned)?;

    let client = BlobClient::new(parsed, credential, None)
        .map_err(|e| Error::Io(format!("creating blob client: {e}")))?;

    let probe = client
        .download(Some(BlobClientDownloadOptions {
            range: Some(HttpRange::new(0, PROBE_LEN)),
            ..Default::default()
        }))
        .await
        .map_err(|e| {
            // The credential is only exercised on the first request, so an auth
            // failure surfaces here rather than at construction. Name the credential
            // that was tried — the SDK's own message does not.
            Error::Io(format!(
                "reading {} failed using the {kind:?} credential: {e} \
                 (check it has Storage Blob Data Reader on the container — account-level \
                 Owner or Contributor does not grant blob read)",
                redact(url),
            ))
        })?;

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

    // The probe *is* the first tar block; keep it rather than paying for it twice.
    let prefetch = probe
        .body
        .collect()
        .await
        .map_err(|e| Error::Io(format!("reading blob probe body: {e}")))?;

    Ok((
        Storage::AzureBlob {
            client: Box::new(client),
            // Pinned so a mid-flight republish fails loudly instead of serving bytes
            // read at stale offsets. See `read_azure_range`.
            etag: etag.clone(),
        },
        ArchiveSource {
            etag,
            last_modified,
            size,
            prefetch: Some(prefetch),
        },
    ))
}

/// Read `length` bytes at `offset` from the blob.
///
/// Every read is conditional on the ETag captured when the archive was opened. The tile
/// index maps ids to byte offsets in one specific version of the blob, so if the archive
/// is replaced while rati is running those offsets now point into different data. Without
/// the guard the service happily returns whatever occupies that range, and rati serves it
/// under the old ETag and `Cache-Control: immutable` — silently poisoning client and CDN
/// caches. With it, Azure answers 412 and the read fails visibly.
pub(super) async fn read_azure_range(
    client: &BlobClient,
    etag: &str,
    offset: u64,
    length: u64,
) -> Result<Bytes, Error> {
    let response = client
        .download(Some(BlobClientDownloadOptions {
            range: Some(HttpRange::new(offset, length)),
            if_match: Some(Etag::from(etag)),
            ..Default::default()
        }))
        .await
        .map_err(|e| {
            Error::Io(format!(
                "blob download(offset={offset}, len={length}): {e} \
                 (a 412 here means the archive was replaced while rati was running; restart it)"
            ))
        })?;

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

        // DNS hostnames are case-insensitive
        assert!(is_azure_url(
            "https://acct.Blob.Core.Windows.Net/tiles/planet.tar"
        ));
        // explicit port, and a fragment, must not defeat the match
        assert!(is_azure_url(
            "https://acct.blob.core.windows.net:443/tiles/planet.tar"
        ));
        // http against a real blob host is still a blob endpoint; routing it here
        // lets us reject it loudly instead of stat()-ing it as a local path
        assert!(is_azure_url(
            "http://acct.blob.core.windows.net/tiles/planet.tar"
        ));

        assert!(!is_azure_url("s3://bucket/planet.tar"));
        assert!(!is_azure_url("./planet.tar"));
        assert!(!is_azure_url("/data/planet.tar"));
        // https, but not a blob endpoint
        assert!(!is_azure_url("https://example.com/planet.tar"));
        // the suffix alone, with no account label, is not a blob URL
        assert!(!is_azure_url("https://blob.core.windows.net/tiles/p.tar"));

        // Azurite's well-known development account, however it is addressed.
        assert!(is_azure_url(
            "http://127.0.0.1:10000/devstoreaccount1/valhalla/tiles.tar"
        ));
        assert!(is_azure_url(
            "http://azurite:10000/devstoreaccount1/valhalla/tiles.tar"
        ));
        assert!(!is_azure_url("http://127.0.0.1:10000/other/c/p.tar"));

        // That account name is matched in the path, so over https -- where a request
        // can carry a bearer token -- a foreign host must not be able to claim it.
        assert!(!is_azure_url(
            "https://attacker.example/devstoreaccount1/c/p.tar"
        ));
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

    const PLAIN: &str = "https://acct.blob.core.windows.net/t/p.tar";
    const SAS: &str = "https://acct.blob.core.windows.net/t/p.tar?sv=1&sig=abc";
    const INSECURE: &str = "http://127.0.0.1:10000/devstoreaccount1/c/p.tar";

    /// An environment with no Azure markers at all — a developer laptop.
    fn bare() -> CredentialEnv {
        CredentialEnv::default()
    }

    /// Azure Container Apps and App Service both inject these.
    fn container_apps() -> CredentialEnv {
        CredentialEnv {
            identity_endpoint: Some("http://169.254.255.2:8081/msi/token".into()),
            ..Default::default()
        }
    }

    /// An AKS pod with the workload-identity webhook.
    fn aks_workload() -> CredentialEnv {
        CredentialEnv {
            federated_token_file: Some("/var/run/secrets/azure/tokens/azure-identity-token".into()),
            ..Default::default()
        }
    }

    /// A GitHub Actions / generic CI service principal.
    fn service_principal_secret() -> CredentialEnv {
        CredentialEnv {
            tenant_id: Some("t".into()),
            client_id: Some("c".into()),
            client_secret: Some("s".into()),
            ..Default::default()
        }
    }

    #[test]
    fn sas_and_plaintext_need_no_credential() {
        use CredentialKind::*;

        // A SAS in the URL authenticates the request on its own.
        assert_eq!(select_credential_kind(SAS, &bare(), None), Anonymous);
        assert_eq!(
            select_credential_kind(SAS, &container_apps(), None),
            Anonymous
        );

        // Never put a bearer token on the wire in the clear, whatever the
        // environment says and even when explicitly asked to.
        assert_eq!(select_credential_kind(INSECURE, &bare(), None), Anonymous);
        assert_eq!(
            select_credential_kind(INSECURE, &container_apps(), None),
            Anonymous
        );
        assert_eq!(
            select_credential_kind(INSECURE, &bare(), Some(ManagedIdentity)),
            Anonymous
        );
    }

    #[test]
    fn azure_hosted_environments_use_managed_identity() {
        use CredentialKind::*;

        // Container Apps: the primary deployment target.
        assert_eq!(
            select_credential_kind(PLAIN, &container_apps(), None),
            ManagedIdentity
        );

        // Cloud Shell / Azure ML expose MSI_ENDPOINT instead.
        let msi = CredentialEnv {
            msi_endpoint: Some("http://localhost:50342/oauth2/token".into()),
            ..Default::default()
        };
        assert_eq!(select_credential_kind(PLAIN, &msi, None), ManagedIdentity);
    }

    #[test]
    fn aks_pods_use_workload_identity() {
        // A federated token file outranks the managed-identity sources: an AKS pod
        // may have both, and the projected token is the one that works.
        assert_eq!(
            select_credential_kind(PLAIN, &aks_workload(), None),
            CredentialKind::WorkloadIdentity
        );

        let both = CredentialEnv {
            federated_token_file: aks_workload().federated_token_file,
            identity_endpoint: container_apps().identity_endpoint,
            ..Default::default()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &both, None),
            CredentialKind::WorkloadIdentity
        );
    }

    #[test]
    fn bare_environment_falls_back_to_the_cli() {
        assert_eq!(
            select_credential_kind(PLAIN, &bare(), None),
            CredentialKind::DeveloperTools
        );
        // Empty markers are not markers.
        let empty = CredentialEnv {
            identity_endpoint: Some(String::new()),
            msi_endpoint: Some(String::new()),
            federated_token_file: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &empty, None),
            CredentialKind::DeveloperTools
        );
    }

    #[test]
    fn service_principals_are_detected_from_the_environment() {
        assert_eq!(
            select_credential_kind(PLAIN, &service_principal_secret(), None),
            CredentialKind::ClientSecret
        );

        // A secret without a tenant is not a usable service principal, so detection
        // must fall through rather than pick a credential that cannot work.
        let partial = CredentialEnv {
            tenant_id: None,
            ..service_principal_secret()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &partial, None),
            CredentialKind::DeveloperTools
        );
    }

    #[test]
    fn federated_token_outranks_a_client_secret() {
        // The workload-identity webhook sets AZURE_CLIENT_ID and AZURE_TENANT_ID too,
        // so a stale secret in the environment must not win over the projected token.
        let pod = CredentialEnv {
            federated_token_file: aks_workload().federated_token_file,
            ..service_principal_secret()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &pod, None),
            CredentialKind::WorkloadIdentity
        );
    }

    #[test]
    fn service_principal_outranks_ambient_managed_identity() {
        // An explicitly configured identity beats whatever the host happens to offer.
        let both = CredentialEnv {
            identity_endpoint: container_apps().identity_endpoint,
            ..service_principal_secret()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &both, None),
            CredentialKind::ClientSecret
        );
    }

    #[test]
    fn explicit_override_wins_over_detection() {
        use CredentialKind::*;

        // A bare Azure VM or VMSS exposes no environment marker at all, so IMDS
        // has to be asked for by name.
        assert_eq!(
            select_credential_kind(PLAIN, &bare(), Some(ManagedIdentity)),
            ManagedIdentity
        );
        // ...and detection can be overridden the other way too.
        assert_eq!(
            select_credential_kind(PLAIN, &container_apps(), Some(DeveloperTools)),
            DeveloperTools
        );
        assert_eq!(
            select_credential_kind(PLAIN, &container_apps(), Some(Anonymous)),
            Anonymous
        );
    }

    #[test]
    fn only_a_blob_host_is_ever_credentialed() {
        use CredentialKind::*;
        const HOSTILE: &str = "https://attacker.example/devstoreaccount1/c/p.tar";

        assert_eq!(
            select_credential_kind(HOSTILE, &container_apps(), None),
            Anonymous
        );
        // ...not even when the operator names a credential explicitly.
        assert_eq!(
            select_credential_kind(HOSTILE, &container_apps(), Some(ManagedIdentity)),
            Anonymous
        );
        assert_eq!(
            select_credential_kind("https://example.com/c/p.tar", &container_apps(), None),
            Anonymous
        );
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
