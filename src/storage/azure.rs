//! Azure Blob Storage backend: byte-range reads against a blob holding the tar archive.

// These helpers are consumed by `open_azure` / `read_azure_range`, added in the
// following commit. Removed once the backend itself lands.
#![allow(dead_code)]

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
