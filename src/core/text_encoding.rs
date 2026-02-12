// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Text encoding support for string/data directives.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TextEncodingId {
    Ascii,
    Petscii,
}

impl TextEncodingId {
    pub fn canonical_name(self) -> &'static str {
        match self {
            TextEncodingId::Ascii => "ascii",
            TextEncodingId::Petscii => "petscii",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextEncodingError {
    UnknownEncoding(String),
    UnmappableByte { encoding: TextEncodingId, byte: u8 },
}

impl std::fmt::Display for TextEncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextEncodingError::UnknownEncoding(name) => write!(f, "Unknown encoding: {name}"),
            TextEncodingError::UnmappableByte { encoding, byte } => write!(
                f,
                "Byte ${byte:02X} is not representable in {}",
                encoding.canonical_name()
            ),
        }
    }
}

impl std::error::Error for TextEncodingError {}

pub struct TextEncodingRegistry {
    names: HashMap<String, TextEncodingId>,
}

impl Default for TextEncodingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TextEncodingRegistry {
    pub fn new() -> Self {
        let mut names = HashMap::new();
        names.insert("ascii".to_string(), TextEncodingId::Ascii);
        names.insert("petscii".to_string(), TextEncodingId::Petscii);
        Self { names }
    }

    pub fn default_encoding(&self) -> TextEncodingId {
        TextEncodingId::Ascii
    }

    pub fn known_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self
            .names
            .values()
            .map(|encoding| encoding.canonical_name())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    pub fn resolve_name(&self, name: &str) -> Option<TextEncodingId> {
        self.names.get(&name.to_ascii_lowercase()).copied()
    }

    pub fn resolve_name_or_error(&self, name: &str) -> Result<TextEncodingId, TextEncodingError> {
        self.resolve_name(name)
            .ok_or_else(|| TextEncodingError::UnknownEncoding(name.to_string()))
    }

    pub fn encode_byte(&self, encoding: TextEncodingId, byte: u8) -> Result<u8, TextEncodingError> {
        match encoding {
            TextEncodingId::Ascii => encode_ascii(byte),
            TextEncodingId::Petscii => encode_petscii(byte),
        }
    }

    pub fn encode_bytes(
        &self,
        encoding: TextEncodingId,
        input: &[u8],
    ) -> Result<Vec<u8>, TextEncodingError> {
        input
            .iter()
            .copied()
            .map(|byte| self.encode_byte(encoding, byte))
            .collect()
    }
}

fn encode_ascii(byte: u8) -> Result<u8, TextEncodingError> {
    if byte <= 0x7F {
        Ok(byte)
    } else {
        Err(TextEncodingError::UnmappableByte {
            encoding: TextEncodingId::Ascii,
            byte,
        })
    }
}

fn encode_petscii(byte: u8) -> Result<u8, TextEncodingError> {
    if byte > 0x7F {
        return Err(TextEncodingError::UnmappableByte {
            encoding: TextEncodingId::Petscii,
            byte,
        });
    }
    if byte.is_ascii_uppercase() {
        return Ok(byte | 0x80);
    }
    if byte.is_ascii_lowercase() {
        return Ok(byte - 0x20);
    }
    Ok(byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_names_case_insensitively() {
        let registry = TextEncodingRegistry::new();
        assert_eq!(registry.resolve_name("ascii"), Some(TextEncodingId::Ascii));
        assert_eq!(registry.resolve_name("ASCII"), Some(TextEncodingId::Ascii));
        assert_eq!(
            registry.resolve_name("petscii"),
            Some(TextEncodingId::Petscii)
        );
        assert_eq!(
            registry.resolve_name("PeTsCiI"),
            Some(TextEncodingId::Petscii)
        );
        assert_eq!(registry.resolve_name("unknown"), None);
    }

    #[test]
    fn ascii_encoding_is_identity_for_7bit_bytes() {
        let registry = TextEncodingRegistry::new();
        let input = b"Az09\r\n\t";
        let out = registry
            .encode_bytes(TextEncodingId::Ascii, input)
            .expect("ascii encodes");
        assert_eq!(out, input);
    }

    #[test]
    fn ascii_rejects_non_7bit_bytes() {
        let registry = TextEncodingRegistry::new();
        let err = registry
            .encode_bytes(TextEncodingId::Ascii, &[0x80])
            .expect_err("ascii should reject high-bit bytes");
        assert_eq!(
            err,
            TextEncodingError::UnmappableByte {
                encoding: TextEncodingId::Ascii,
                byte: 0x80,
            }
        );
    }

    #[test]
    fn petscii_maps_letters_and_preserves_non_letters() {
        let registry = TextEncodingRegistry::new();
        let out = registry
            .encode_bytes(TextEncodingId::Petscii, b"Az09")
            .expect("petscii encodes");
        assert_eq!(out, vec![0xC1, 0x5A, b'0', b'9']);
    }

    #[test]
    fn petscii_rejects_non_7bit_bytes() {
        let registry = TextEncodingRegistry::new();
        let err = registry
            .encode_bytes(TextEncodingId::Petscii, &[0xFF])
            .expect_err("petscii should reject high-bit bytes");
        assert_eq!(
            err,
            TextEncodingError::UnmappableByte {
                encoding: TextEncodingId::Petscii,
                byte: 0xFF,
            }
        );
    }
}
