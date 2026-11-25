//! Encoders/decoders for the Tools module (Phase 2): base64, hex, URL, HTML
//! entity, and ROT13 transforms. Pure, deterministic, offline. Used by payload
//! crafting, evidence normalization, and manual triage.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Codec {
    Base64,
    Hex,
    Url,
    HtmlEntity,
    Rot13,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("invalid input for {0}: {1}")]
    Invalid(String, String),
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, CodecError> {
    let inv = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let cleaned: Vec<u8> = s.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    let trimmed: Vec<u8> = cleaned.iter().copied().filter(|&b| b != b'=').collect();
    let mut out = Vec::new();
    for chunk in trimmed.chunks(4) {
        let mut n = 0u32;
        let mut bits = 0;
        for &c in chunk {
            let v = inv(c).ok_or_else(|| CodecError::Invalid("base64".into(), format!("bad char '{}'", c as char)))?;
            n = (n << 6) | v;
            bits += 6;
        }
        n <<= 24 - bits;
        let bytes = (bits / 8) as usize;
        for i in 0..bytes {
            out.push(((n >> (16 - i * 8)) & 0xFF) as u8);
        }
    }
    Ok(out)
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn url_decode(s: &str) -> Result<String, CodecError> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                let v = u8::from_str_radix(hex, 16).map_err(|_| CodecError::Invalid("url".into(), format!("bad %{hex}")))?;
                out.push(v);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| CodecError::Invalid("url".into(), e.to_string()))
}

fn html_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#x27;".into(),
            c => c.to_string(),
        })
        .collect()
}

fn html_decode(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
}

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            c => c,
        })
        .collect()
}

/// Encode input with the given codec.
pub fn encode(codec: Codec, input: &str) -> String {
    match codec {
        Codec::Base64 => b64_encode(input.as_bytes()),
        Codec::Hex => input.bytes().map(|b| format!("{b:02x}")).collect(),
        Codec::Url => url_encode(input),
        Codec::HtmlEntity => html_encode(input),
        Codec::Rot13 => rot13(input),
    }
}

/// Decode input with the given codec.
pub fn decode(codec: Codec, input: &str) -> Result<String, CodecError> {
    match codec {
        Codec::Base64 => {
            let bytes = b64_decode(input)?;
            String::from_utf8(bytes).map_err(|e| CodecError::Invalid("base64".into(), e.to_string()))
        }
        Codec::Hex => {
            let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
            if clean.len() % 2 != 0 {
                return Err(CodecError::Invalid("hex".into(), "odd length".into()));
            }
            let mut out = Vec::new();
            let b = clean.as_bytes();
            let mut i = 0;
            while i < b.len() {
                let pair = std::str::from_utf8(&b[i..i + 2]).unwrap_or("");
                out.push(u8::from_str_radix(pair, 16).map_err(|_| CodecError::Invalid("hex".into(), format!("bad {pair}")))?);
                i += 2;
            }
            String::from_utf8(out).map_err(|e| CodecError::Invalid("hex".into(), e.to_string()))
        }
        Codec::Url => url_decode(input),
        Codec::HtmlEntity => Ok(html_decode(input)),
        Codec::Rot13 => Ok(rot13(input)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let enc = encode(Codec::Base64, "Hello, FableScope!");
        assert_eq!(enc, "SGVsbG8sIEZhYmxlU2NvcGUh");
        assert_eq!(decode(Codec::Base64, &enc).unwrap(), "Hello, FableScope!");
    }

    #[test]
    fn hex_roundtrip() {
        let enc = encode(Codec::Hex, "AB");
        assert_eq!(enc, "4142");
        assert_eq!(decode(Codec::Hex, "4142").unwrap(), "AB");
    }

    #[test]
    fn url_roundtrip() {
        let enc = encode(Codec::Url, "a b&c=d");
        assert_eq!(enc, "a%20b%26c%3Dd");
        assert_eq!(decode(Codec::Url, &enc).unwrap(), "a b&c=d");
    }

    #[test]
    fn html_roundtrip() {
        let enc = encode(Codec::HtmlEntity, "<script>");
        assert_eq!(enc, "&lt;script&gt;");
        assert_eq!(decode(Codec::HtmlEntity, &enc).unwrap(), "<script>");
    }

    #[test]
    fn rot13_is_involution() {
        assert_eq!(decode(Codec::Rot13, &encode(Codec::Rot13, "Attack")).unwrap(), "Attack");
    }

    #[test]
    fn invalid_hex_errors() {
        assert!(decode(Codec::Hex, "xyz").is_err());
    }
}
