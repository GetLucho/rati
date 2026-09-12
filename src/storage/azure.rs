//! Azure Blob Storage backend: byte-range reads against a blob holding the tar archive.

use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_core::http::Etag;
use azure_core::http::Url;
use azure_core::http::headers::HeaderName;
use azure_identity::{
    AzurePipelinesCredential, ClientSecretCredential, DeveloperToolsCredential,
    ManagedIdentityCredential, ManagedIdentityCredentialOptions, UserAssignedId,
    WorkloadIdentityCredential,
};
use azure_storage_blob::BlobClient;
use azure_storage_blob::models::{BlobClientDownloadOptions, HttpRange};
use bytes::Bytes;

use super::{ArchiveSource, Storage, redact};
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

/// True when `source` is an HTTP(S) URL pointing at an Azure Blob endpoint.
///
/// `http` counts: routing an insecure blob URL here lets [`open_azure`] reject or
/// downgrade it deliberately, rather than letting it fall through and be `stat()`ed
/// as a local filesystem path.
pub(super) fn is_azure_url(source: &str) -> bool {
    let Ok(url) = Url::parse(source) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    // `Url` lowercases the host during parsing; hostnames are case-insensitive.
    let Some(host) = url.host_str() else {
        return false;
    };
    BLOB_HOST_SUFFIXES
        .iter()
        .any(|suffix| host.len() > suffix.len() && host.ends_with(suffix))
        || is_emulator_url(source)
}

/// True when the URL addresses the storage emulator's well-known account, which is
/// how Azurite is reached (`http://127.0.0.1:10000/devstoreaccount1/...`).
pub(super) fn is_emulator_url(source: &str) -> bool {
    let Ok(url) = Url::parse(source) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    url.path_segments()
        .and_then(|mut segments| segments.next())
        .is_some_and(|account| account == EMULATOR_ACCOUNT)
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
///
/// `azure_identity` 1.0 ships no `DefaultAzureCredential`, so rati selects one
/// explicitly rather than chaining and probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CredentialKind {
    /// No credential: a SAS in the URL, a public container, or a plaintext endpoint.
    Anonymous,
    /// An Azure Pipelines service connection (`SYSTEM_OIDCREQUESTURI`).
    AzurePipelines,
    /// Entra Workload ID — an AKS pod with a projected federated token.
    WorkloadIdentity,
    /// A service principal holding a certificate. Requires the
    /// `azure-client-certificate` cargo feature, which links OpenSSL.
    ClientCertificate,
    /// A service principal holding a secret — the usual CI credential.
    ClientSecret,
    /// A managed identity: Container Apps, App Service, Arc, Cloud Shell, or IMDS
    /// on a plain VM or VMSS.
    ManagedIdentity,
    /// Local development; chains the az and azd CLIs.
    DeveloperTools,
}

/// Which kind of id `--azure-user-assigned-id` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum UserAssignedIdKind {
    /// The identity's client (application) id. The usual choice.
    #[default]
    Client,
    /// The identity's object (principal) id.
    Object,
    /// The identity's full ARM resource id.
    Resource,
}

/// The environment markers that identify where rati is running.
///
/// Captured as a struct so the selection below is a pure function and can be
/// tested without mutating process-wide environment state.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct CredentialEnv<'a> {
    /// Set by Container Apps, App Service and Azure Arc.
    pub identity_endpoint: Option<&'a str>,
    /// Set by Cloud Shell and Azure ML.
    pub msi_endpoint: Option<&'a str>,
    /// Set by the AKS workload-identity webhook.
    pub federated_token_file: Option<&'a str>,
    /// Set inside an Azure Pipelines job that has an OIDC-capable connection.
    pub oidc_request_uri: Option<&'a str>,
    /// Service-principal tenant. Required by every service-principal credential.
    pub tenant_id: Option<&'a str>,
    /// Service-principal application id.
    pub client_id: Option<&'a str>,
    /// Service-principal secret.
    pub client_secret: Option<&'a str>,
    /// PEM or PKCS#12 file holding a service-principal certificate.
    pub client_certificate_path: Option<&'a str>,
}

impl CredentialEnv<'static> {
    /// Read the markers from the process environment.
    fn from_process() -> Self {
        fn var(key: &str) -> Option<&'static str> {
            // Leaked so the struct can borrow for 'static; there are at most three
            // of these and they live as long as the process anyway.
            std::env::var(key)
                .ok()
                .filter(|v| !v.is_empty())
                .map(|v| &*Box::leak(v.into_boxed_str()))
        }
        Self {
            identity_endpoint: var("IDENTITY_ENDPOINT"),
            msi_endpoint: var("MSI_ENDPOINT"),
            federated_token_file: var("AZURE_FEDERATED_TOKEN_FILE"),
            oidc_request_uri: var("SYSTEM_OIDCREQUESTURI"),
            tenant_id: var("AZURE_TENANT_ID"),
            client_id: var("AZURE_CLIENT_ID"),
            client_secret: var("AZURE_CLIENT_SECRET"),
            client_certificate_path: var("AZURE_CLIENT_CERTIFICATE_PATH"),
        }
    }
}

/// Pick a credential from the URL, the ambient environment, and an optional
/// explicit override.
///
/// Detection order matters. A federated token file outranks the managed-identity
/// markers because an AKS pod can carry both, and only the projected token works.
/// A plain Azure VM or VMSS exposes *no* marker — IMDS is reachable but invisible —
/// so that case must be requested by name via `override_kind`.
pub(super) fn select_credential_kind(
    url: &str,
    env: &CredentialEnv<'_>,
    override_kind: Option<CredentialKind>,
) -> CredentialKind {
    // A bearer token must never go out over plaintext, so an http endpoint is
    // anonymous whatever the environment or the operator says. The SDK rejects the
    // combination too, but reports it as an opaque client-construction failure.
    let insecure = Url::parse(url).is_ok_and(|u| u.scheme() != "https");
    if insecure || has_sas_token(url) {
        return CredentialKind::Anonymous;
    }

    if let Some(kind) = override_kind {
        return kind;
    }

    let set = |v: Option<&str>| v.is_some_and(|s| !s.is_empty());
    let service_principal = set(env.tenant_id) && set(env.client_id);

    // Ordering mirrors DefaultAzureCredential in the other Azure SDKs: an
    // explicitly configured identity outranks an ambient one, and the most
    // specific marker wins. A pod or pipeline can carry several of these at once.
    if set(env.oidc_request_uri) && service_principal {
        CredentialKind::AzurePipelines
    } else if set(env.federated_token_file) {
        CredentialKind::WorkloadIdentity
    } else if service_principal && set(env.client_certificate_path) {
        CredentialKind::ClientCertificate
    } else if service_principal && set(env.client_secret) {
        CredentialKind::ClientSecret
    } else if set(env.identity_endpoint) || set(env.msi_endpoint) {
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

/// A nudge toward the usual cause when a given credential cannot get a token.
fn credential_hint(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::Anonymous => {
            " (no credential was used: the URL has no SAS, or the endpoint is plaintext \
             — the container must allow anonymous read)"
        }
        CredentialKind::ManagedIdentity => {
            " (IMDS is only reachable from Azure-hosted compute; off Azure, use \
             --azure-credential developer-tools and `az login`)"
        }
        CredentialKind::WorkloadIdentity => {
            " (AZURE_FEDERATED_TOKEN_FILE is set but the projected token was rejected; \
             check the federated credential and that the identity has Storage Blob Data Reader)"
        }
        CredentialKind::DeveloperTools => {
            " (no Azure environment markers were found; run `az login`, or name a \
             credential with --azure-credential)"
        }
        CredentialKind::ClientSecret | CredentialKind::ClientCertificate => {
            " (check AZURE_TENANT_ID / AZURE_CLIENT_ID and that the service principal \
             has Storage Blob Data Reader)"
        }
        CredentialKind::AzurePipelines => {
            " (check the service connection is OIDC-capable and SYSTEM_ACCESSTOKEN is \
             exposed to this step)"
        }
    }
}

/// Required environment variable, reported by name when absent.
fn require<'a>(value: Option<&'a str>, name: &str, kind: CredentialKind) -> Result<&'a str, Error> {
    value
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::Protocol(format!("{kind:?} credential needs {name} to be set")))
}

/// Build the credential rati presents to Azure Blob for `url`.
fn build_credential(
    url: &str,
    user_assigned: Option<(&str, UserAssignedIdKind)>,
    service_connection_id: Option<&str>,
    override_kind: Option<CredentialKind>,
) -> Result<Option<Arc<dyn TokenCredential>>, Error> {
    let env = CredentialEnv::from_process();
    let kind = select_credential_kind(url, &env, override_kind);
    tracing::info!("Azure credential: {kind:?}");

    match kind {
        CredentialKind::Anonymous => Ok(None),

        CredentialKind::AzurePipelines => {
            let tenant = require(env.tenant_id, "AZURE_TENANT_ID", kind)?;
            let client = require(env.client_id, "AZURE_CLIENT_ID", kind)?;
            let connection = service_connection_id
                .or(env_var_static("AZURE_SERVICE_CONNECTION_ID"))
                .ok_or_else(|| {
                    Error::Protocol(
                        "AzurePipelines credential needs --azure-service-connection-id \
                         (or AZURE_SERVICE_CONNECTION_ID)"
                            .into(),
                    )
                })?;
            let token = require(
                env_var_static("SYSTEM_ACCESSTOKEN"),
                "SYSTEM_ACCESSTOKEN",
                kind,
            )?;
            let credential = AzurePipelinesCredential::new(
                tenant.to_string(),
                client.to_string(),
                connection,
                token.to_string(),
                None,
            )
            .map_err(|e| Error::Io(format!("azure pipelines credential: {e}")))?;
            Ok(Some(credential))
        }

        CredentialKind::WorkloadIdentity => {
            let credential = WorkloadIdentityCredential::new(None)
                .map_err(|e| Error::Io(format!("workload identity credential: {e}")))?;
            Ok(Some(credential))
        }

        #[cfg(feature = "azure-client-certificate")]
        CredentialKind::ClientCertificate => {
            let tenant = require(env.tenant_id, "AZURE_TENANT_ID", kind)?;
            let client = require(env.client_id, "AZURE_CLIENT_ID", kind)?;
            let path = require(
                env.client_certificate_path,
                "AZURE_CLIENT_CERTIFICATE_PATH",
                kind,
            )?;
            let bytes = std::fs::read(path)
                .map_err(|e| Error::Io(format!("reading certificate {path}: {e}")))?;
            let credential = azure_identity::ClientCertificateCredential::new(
                tenant.to_string(),
                client.to_string(),
                bytes.into(),
                None,
            )
            .map_err(|e| Error::Io(format!("client certificate credential: {e}")))?;
            Ok(Some(credential))
        }
        #[cfg(not(feature = "azure-client-certificate"))]
        CredentialKind::ClientCertificate => Err(Error::Protocol(
            "AZURE_CLIENT_CERTIFICATE_PATH is set, but this build has no certificate \
             support: rebuild with --features azure-client-certificate (it links OpenSSL), \
             or use a client secret instead"
                .into(),
        )),

        CredentialKind::ClientSecret => {
            let tenant = require(env.tenant_id, "AZURE_TENANT_ID", kind)?;
            let client = require(env.client_id, "AZURE_CLIENT_ID", kind)?;
            let secret = require(env.client_secret, "AZURE_CLIENT_SECRET", kind)?;
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
            let options = user_assigned.map(|(id, kind)| ManagedIdentityCredentialOptions {
                user_assigned_id: Some(match kind {
                    UserAssignedIdKind::Client => UserAssignedId::ClientId(id.to_string()),
                    UserAssignedIdKind::Object => UserAssignedId::ObjectId(id.to_string()),
                    UserAssignedIdKind::Resource => UserAssignedId::ResourceId(id.to_string()),
                }),
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

/// Read an environment variable, leaked so it can be borrowed for `'static`.
/// Only ever called a handful of times, at startup.
fn env_var_static(key: &str) -> Option<&'static str> {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| &*Box::leak(v.into_boxed_str()))
}

/// Open the archive from Azure Blob Storage.
///
/// Reads the leading tar block to pick up the blob's ETag, Last-Modified, and total
/// size in one request: `get_properties` returns its values as raw headers, whereas a
/// ranged `download` hands back a typed `BlobDownloadProperties`.
pub(super) async fn open_azure(
    url: &str,
    user_assigned: Option<(&str, UserAssignedIdKind)>,
    service_connection_id: Option<&str>,
    override_kind: Option<CredentialKind>,
) -> Result<(Storage, ArchiveSource), Error> {
    let parsed = Url::parse(url)
        .map_err(|e| Error::Protocol(format!("invalid blob URL {}: {e}", redact(url))))?;
    let kind = select_credential_kind(url, &CredentialEnv::from_process(), override_kind);
    let credential = build_credential(url, user_assigned, service_connection_id, override_kind)?;

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
                "reading {} failed using the {kind:?} credential: {e}{}",
                redact(url),
                credential_hint(kind)
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

    let data = response
        .body
        .collect()
        .await
        .map_err(|e| Error::Io(format!("reading blob response body: {e}")))?;

    // fix 3: the callers index into what comes back assuming it is exactly `length`
    // bytes; `scan_tar_headers` subtracts from `chunk.len()` and would underflow.
    if data.len() as u64 != length {
        return Err(Error::Io(format!(
            "short read at offset={offset}: asked for {length} bytes, got {}",
            data.len()
        )));
    }
    Ok(data)
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
    fn bare() -> CredentialEnv<'static> {
        CredentialEnv::default()
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
            select_credential_kind(INSECURE, &bare(), Some(CredentialKind::ManagedIdentity)),
            Anonymous
        );
    }

    /// Azure Container Apps and App Service both inject these.
    fn container_apps() -> CredentialEnv<'static> {
        CredentialEnv {
            identity_endpoint: Some("http://169.254.255.2:8081/msi/token"),
            ..Default::default()
        }
    }

    /// An AKS pod with the workload-identity webhook.
    fn aks_workload() -> CredentialEnv<'static> {
        CredentialEnv {
            federated_token_file: Some("/var/run/secrets/azure/tokens/azure-identity-token"),
            ..Default::default()
        }
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
            msi_endpoint: Some("http://localhost:50342/oauth2/token"),
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
            identity_endpoint: Some(""),
            msi_endpoint: Some(""),
            federated_token_file: Some(""),
            ..Default::default()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &empty, None),
            CredentialKind::DeveloperTools
        );
    }

    /// A GitHub Actions / generic CI service principal.
    fn service_principal_secret() -> CredentialEnv<'static> {
        CredentialEnv {
            tenant_id: Some("t"),
            client_id: Some("c"),
            client_secret: Some("s"),
            ..Default::default()
        }
    }

    #[test]
    fn service_principals_are_detected_from_the_environment() {
        use CredentialKind::*;

        assert_eq!(
            select_credential_kind(PLAIN, &service_principal_secret(), None),
            ClientSecret
        );

        let cert = CredentialEnv {
            client_secret: None,
            client_certificate_path: Some("/run/secrets/sp.pem"),
            ..service_principal_secret()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &cert, None),
            ClientCertificate
        );

        // A certificate outranks a secret when both are configured.
        let both = CredentialEnv {
            client_certificate_path: Some("/run/secrets/sp.pem"),
            ..service_principal_secret()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &both, None),
            ClientCertificate
        );

        // A secret without a tenant is not a usable service principal, so detection
        // must fall through rather than pick a credential that cannot work.
        let partial = CredentialEnv {
            tenant_id: None,
            ..service_principal_secret()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &partial, None),
            DeveloperTools
        );
    }

    #[test]
    fn azure_pipelines_outranks_other_service_principal_markers() {
        let pipeline = CredentialEnv {
            oidc_request_uri: Some("https://dev.azure.com/o/_apis/distributedtask/oidctoken"),
            ..service_principal_secret()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &pipeline, None),
            CredentialKind::AzurePipelines
        );

        // ...but the OIDC endpoint alone, without a service principal, is not enough.
        let uri_only = CredentialEnv {
            oidc_request_uri: Some("https://dev.azure.com/o/_apis/distributedtask/oidctoken"),
            ..Default::default()
        };
        assert_eq!(
            select_credential_kind(PLAIN, &uri_only, None),
            CredentialKind::DeveloperTools
        );
    }

    #[test]
    fn federated_token_outranks_a_client_secret() {
        // The workload-identity webhook sets AZURE_CLIENT_ID and AZURE_TENANT_ID too,
        // so a stale secret in the environment must not win over the projected token.
        let pod = CredentialEnv {
            federated_token_file: Some("/var/run/secrets/azure/tokens/azure-identity-token"),
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
    fn is_emulator_url_test() {
        // Azurite's well-known development account, however it is addressed.
        assert!(is_emulator_url(
            "http://127.0.0.1:10000/devstoreaccount1/valhalla/tiles.tar"
        ));
        assert!(is_emulator_url(
            "http://azurite:10000/devstoreaccount1/valhalla/tiles.tar"
        ));

        assert!(!is_emulator_url(
            "https://acct.blob.core.windows.net/devstoreaccount1x/t.tar"
        ));
        assert!(!is_emulator_url("http://127.0.0.1:10000/other/c/p.tar"));
        assert!(!is_emulator_url("/data/planet.tar"));
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
