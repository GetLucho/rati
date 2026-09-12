//! Filesystem-backed tar archive: `stat` for metadata, positional reads for ranges.

use std::sync::Arc;

use bytes::Bytes;

use super::{ArchiveSource, Storage};
use crate::archive::Error;

/// Format a `SystemTime` as an HTTP-date (RFC 9110 IMF-fixdate).
fn format_http_date(t: std::time::SystemTime) -> String {
    httpdate::fmt_http_date(t)
}

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
    let last_modified: Box<str> = format_http_date(mtime).into();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date_format_matches_imf_fixdate() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_744_891_200);
        assert_eq!(format_http_date(t), "Thu, 17 Apr 2025 12:00:00 GMT");
    }
}
