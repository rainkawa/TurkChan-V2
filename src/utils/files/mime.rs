use anyhow::Result;

/// Detect the MIME type of an uploaded file from its magic bytes.
///
/// # Errors
/// Returns an error when the header is empty or the file type is not one of
/// `TurkChan`'s accepted upload formats.
pub(super) fn detect_mime_type(data: &[u8]) -> Result<&'static str> {
    if data.is_empty() {
        return Err(anyhow::anyhow!("File is empty."));
    }
    let header = data.get(..data.len().min(12)).unwrap_or(data);

    if data.get(4..8) == Some(b"ftyp") {
        if let Some(brand) = data.get(8..12) {
            // AVIF shares the ISO base-media container with HEIC, so it is
            // declared by its brand rather than by a distinct header. The
            // image sequence brand is `av01` rather than `avif`.
            if has_ftyp_brand(data, &[b"avif", b"avis"]) || has_ftyp_brand(data, &[b"av01"]) {
                return Ok("image/avif");
            }
            if has_ftyp_brand(data, &[b"heic", b"heix", b"hevc", b"hevx"]) {
                return Ok("image/heic");
            }
            if has_ftyp_brand(data, &[b"mif1", b"msf1"]) {
                return Ok("image/heif");
            }
            if brand == b"M4A " || brand == b"m4a " {
                return Ok("audio/mp4");
            }
        }
        return Ok("video/mp4");
    }

    if header.starts_with(b"RIFF") {
        return match data.get(8..12) {
            Some(b"WEBP") => Ok("image/webp"),
            Some(b"WAVE") => Ok("audio/wav"),
            _ => Err(anyhow::anyhow!(
                "RIFF container with unknown subtype. Accepted: WebP, WAV"
            )),
        };
    }

    if header.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        let scan = data.get(..data.len().min(512)).unwrap_or(data);
        if let Some(doc_type) = ebml_doc_type(scan) {
            if doc_type.eq_ignore_ascii_case(b"webm") {
                return Ok("video/webm");
            }
            if doc_type.eq_ignore_ascii_case(b"matroska") {
                return Ok("video/x-matroska");
            }
        }
        return Err(anyhow::anyhow!(
            "File type not allowed. EBML container is not valid WebM or Matroska/MKV media."
        ));
    }

    if header.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Ok("image/jpeg");
    }
    if header.starts_with(b"\x89PNG\r\n\x1A\n") {
        return Ok("image/png");
    }
    if header.starts_with(b"%PDF-") {
        return Ok("application/pdf");
    }
    if header.starts_with(b"GIF87a") || header.starts_with(b"GIF89a") {
        return Ok("image/gif");
    }
    if header.starts_with(b"ID3") || matches!(header.get(..2), Some([0xFF, 0xFB | 0xF3 | 0xF2])) {
        return Ok("audio/mpeg");
    }
    if header.starts_with(&[0xFF, 0xF1]) || header.starts_with(&[0xFF, 0xF9]) {
        return Ok("audio/aac");
    }
    if header.starts_with(b"OggS") {
        if data
            .get(..data.len().min(512))
            .is_some_and(|scan| scan.windows(b"OpusHead".len()).any(|w| w == b"OpusHead"))
        {
            return Ok("audio/opus");
        }
        return Ok("audio/ogg");
    }
    if header.starts_with(b"fLaC") {
        return Ok("audio/flac");
    }
    if header.starts_with(b"BM") {
        return Ok("image/bmp");
    }
    if header.starts_with(b"II*\0") || header.starts_with(b"MM\0*") {
        return Ok("image/tiff");
    }

    let probe = data.get(..data.len().min(256)).unwrap_or(data);
    if let Ok(text) = std::str::from_utf8(probe) {
        let trimmed = text.trim_start_matches('\u{FEFF}').trim_start();
        if trimmed.starts_with("<svg")
            || trimmed.starts_with("<?xml") && trimmed.to_ascii_lowercase().contains("<svg")
        {
            return Ok("image/svg+xml");
        }
    }

    Err(anyhow::anyhow!(
        "File type not allowed. Accepted: JPEG, PNG, GIF, WebP, AVIF, HEIC, HEIF, BMP, TIFF, \
         MP4, WebM, MP3, OGG, FLAC, WAV, M4A, AAC, PDF"
    ))
}

/// Return whether an ISO base-media header declares any accepted brand.
fn has_ftyp_brand(data: &[u8], accepted: &[&[u8; 4]]) -> bool {
    data.get(8..data.len().min(64)).is_some_and(|brands| {
        let (brands, _) = brands.as_chunks::<4>();
        brands.iter().any(|brand| accepted.contains(&brand))
    })
}

/// Extract a bounded EBML document-type value from the sniff buffer.
fn ebml_doc_type(scan: &[u8]) -> Option<&[u8]> {
    let pos = scan.windows(2).position(|w| w == [0x42, 0x82])?;
    let size_idx = pos.checked_add(2)?;
    let size = *scan.get(size_idx)?;
    let len = usize::from(size & 0x7F);
    if len == 0 || len > 32 {
        return None;
    }
    let start = size_idx.checked_add(1)?;
    let end = start.checked_add(len)?;
    scan.get(start..end)
}

#[must_use]
/// Return the safe generic MIME type used for unrecognized downloads.
pub const fn fallback_download_mime_type() -> &'static str {
    "application/octet-stream"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ftyp_brand_chunks_ignore_incomplete_trailing_bytes() {
        let accepted = &[b"heic"];

        assert!(!has_ftyp_brand(b"", accepted));
        assert!(!has_ftyp_brand(b"00000000hei", accepted));
        assert!(has_ftyp_brand(b"00000000heic", accepted));
        assert!(has_ftyp_brand(b"00000000heicx", accepted));
        assert!(has_ftyp_brand(b"00000000heicxy", accepted));
        assert!(!has_ftyp_brand(b"00000000xxxxhei", accepted));
    }

    /// AVIF and HEIC share one ISO base-media container, so only the declared
    /// brand tells them apart. A file that declares AVIF must be read as AVIF
    /// rather than falling through to the HEIC branch beside it, and a file
    /// that declares HEIC must not be read as AVIF either — otherwise the
    /// format stored and the format the reader was told about would disagree.
    #[test]
    fn avif_and_heic_are_told_apart_by_their_declared_brand() {
        let avif = b"\0\0\0\x20ftypavif\0\0\0\0avifmif1miaf";
        let heic = b"\0\0\0\x20ftypheic\0\0\0\0heicmif1miaf";

        assert_eq!(
            detect_mime_type(avif).unwrap_or_default(),
            "image/avif",
            "an AVIF brand must be detected as AVIF"
        );
        assert_eq!(
            detect_mime_type(heic).unwrap_or_default(),
            "image/heic",
            "a HEIC brand must stay HEIC"
        );
        // The image sequence brand sits beside the major brand, and an AVIF
        // file may declare it in either position.
        assert_eq!(
            detect_mime_type(b"\0\0\0\x20ftypavif\0\0\0\0av01miaf").unwrap_or_default(),
            "image/avif"
        );
        assert_eq!(
            detect_mime_type(b"\0\0\0\x20ftypmif1\0\0\0\0av01miaf").unwrap_or_default(),
            "image/avif",
            "an AVIF file may declare its image sequence brand first"
        );
        assert_eq!(
            detect_mime_type(b"\0\0\0\x20ftypisom\0\0\0\0mp42").unwrap_or_default(),
            "video/mp4",
            "a brand that names neither format stays the generic MP4"
        );
    }
}
