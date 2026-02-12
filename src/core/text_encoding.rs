// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Text encoding support for string/data directives.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextEncodingError {
    UnknownEncoding(String),
    InvalidEncodingName,
    MissingCharMapping { encoding: String, byte: u8 },
    CharacterAlreadyDefined { encoding: String, byte: u8 },
    InvalidRange { start: u8, end: u8 },
    EncodedValueOverflow { encoding: String, value: u32 },
    TdefLengthMismatch { chars: usize, values: usize },
    EmptyEscapePattern { encoding: String },
}

impl std::fmt::Display for TextEncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextEncodingError::UnknownEncoding(name) => write!(f, "Unknown encoding: {name}"),
            TextEncodingError::InvalidEncodingName => {
                write!(f, "Encoding name must not be empty")
            }
            TextEncodingError::MissingCharMapping { encoding, byte } => {
                write!(f, "Byte ${byte:02X} is not representable in {encoding}")
            }
            TextEncodingError::CharacterAlreadyDefined { encoding, byte } => {
                write!(f, "Byte ${byte:02X} is already defined in {encoding}")
            }
            TextEncodingError::InvalidRange { start, end } => {
                write!(f, "Invalid character range ${start:02X}..${end:02X}")
            }
            TextEncodingError::EncodedValueOverflow { encoding, value } => {
                write!(f, "Value ${value:X} does not fit in a byte for {encoding}")
            }
            TextEncodingError::TdefLengthMismatch { chars, values } => {
                write!(
                    f,
                    "tdef value count ({values}) does not match char count ({chars})"
                )
            }
            TextEncodingError::EmptyEscapePattern { encoding } => {
                write!(f, "edef escape text must not be empty in {encoding}")
            }
        }
    }
}

impl std::error::Error for TextEncodingError {}

#[derive(Debug, Clone, Default)]
struct EncodingDefinition {
    char_map: HashMap<u8, u8>,
    escapes: Vec<EscapeDefinition>,
}

#[derive(Debug, Clone)]
struct EscapeDefinition {
    pattern: Vec<u8>,
    replacement: Vec<u8>,
}

impl EncodingDefinition {
    fn define_char(
        &mut self,
        encoding: &str,
        source: u8,
        mapped: u8,
    ) -> Result<(), TextEncodingError> {
        if self.char_map.contains_key(&source) {
            return Err(TextEncodingError::CharacterAlreadyDefined {
                encoding: encoding.to_string(),
                byte: source,
            });
        }
        self.char_map.insert(source, mapped);
        Ok(())
    }

    fn define_range(
        &mut self,
        encoding: &str,
        start: u8,
        end: u8,
        coded: u32,
    ) -> Result<(), TextEncodingError> {
        if start > end {
            return Err(TextEncodingError::InvalidRange { start, end });
        }
        for byte in start..=end {
            let mapped = coded + (byte - start) as u32;
            if mapped > u8::MAX as u32 {
                return Err(TextEncodingError::EncodedValueOverflow {
                    encoding: encoding.to_string(),
                    value: mapped,
                });
            }
            self.define_char(encoding, byte, mapped as u8)?;
        }
        Ok(())
    }

    fn define_tdef_increment(
        &mut self,
        encoding: &str,
        chars: &[u8],
        start_value: u32,
    ) -> Result<(), TextEncodingError> {
        for (idx, byte) in chars.iter().copied().enumerate() {
            let mapped = start_value + idx as u32;
            if mapped > u8::MAX as u32 {
                return Err(TextEncodingError::EncodedValueOverflow {
                    encoding: encoding.to_string(),
                    value: mapped,
                });
            }
            self.define_char(encoding, byte, mapped as u8)?;
        }
        Ok(())
    }

    fn define_tdef_values(
        &mut self,
        encoding: &str,
        chars: &[u8],
        values: &[u8],
    ) -> Result<(), TextEncodingError> {
        if chars.len() != values.len() {
            return Err(TextEncodingError::TdefLengthMismatch {
                chars: chars.len(),
                values: values.len(),
            });
        }
        for (source, mapped) in chars.iter().copied().zip(values.iter().copied()) {
            self.define_char(encoding, source, mapped)?;
        }
        Ok(())
    }

    fn define_escape(
        &mut self,
        encoding: &str,
        pattern: &[u8],
        replacement: &[u8],
    ) -> Result<(), TextEncodingError> {
        if pattern.is_empty() {
            return Err(TextEncodingError::EmptyEscapePattern {
                encoding: encoding.to_string(),
            });
        }
        if let Some(existing) = self
            .escapes
            .iter_mut()
            .find(|item| item.pattern.as_slice() == pattern)
        {
            existing.replacement = replacement.to_vec();
            return Ok(());
        }
        self.escapes.push(EscapeDefinition {
            pattern: pattern.to_vec(),
            replacement: replacement.to_vec(),
        });
        Ok(())
    }

    fn encode_bytes(&self, encoding: &str, input: &[u8]) -> Result<Vec<u8>, TextEncodingError> {
        let mut out = Vec::with_capacity(input.len());
        let mut index = 0usize;
        while index < input.len() {
            if let Some(escape) = self.longest_escape_at(input, index) {
                out.extend_from_slice(&escape.replacement);
                index += escape.pattern.len();
                continue;
            }
            let source = input[index];
            let mapped = self.char_map.get(&source).copied().ok_or_else(|| {
                TextEncodingError::MissingCharMapping {
                    encoding: encoding.to_string(),
                    byte: source,
                }
            })?;
            out.push(mapped);
            index += 1;
        }
        Ok(out)
    }

    fn longest_escape_at(&self, input: &[u8], start: usize) -> Option<&EscapeDefinition> {
        let mut best: Option<&EscapeDefinition> = None;
        for escape in &self.escapes {
            if start + escape.pattern.len() > input.len() {
                continue;
            }
            if !input[start..].starts_with(&escape.pattern) {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|prev| escape.pattern.len() > prev.pattern.len())
            {
                best = Some(escape);
            }
        }
        best
    }
}

pub struct TextEncodingRegistry {
    encodings: HashMap<String, EncodingDefinition>,
    default_encoding: String,
}

impl Default for TextEncodingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TextEncodingRegistry {
    pub fn new() -> Self {
        let mut encodings = HashMap::new();
        encodings.insert("ascii".to_string(), Self::builtin_ascii());
        encodings.insert("petscii".to_string(), Self::builtin_petscii());
        Self {
            encodings,
            default_encoding: "ascii".to_string(),
        }
    }

    pub fn default_encoding_name(&self) -> &str {
        &self.default_encoding
    }

    pub fn known_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.encodings.keys().cloned().collect();
        names.sort();
        names
    }

    pub fn resolve_name(&self, name: &str) -> Option<String> {
        let normalized = normalize_name(name).ok()?;
        self.encodings
            .contains_key(&normalized)
            .then_some(normalized)
    }

    pub fn ensure_encoding(&mut self, name: &str) -> Result<String, TextEncodingError> {
        let normalized = normalize_name(name)?;
        self.encodings.entry(normalized.clone()).or_default();
        Ok(normalized)
    }

    pub fn ensure_encoding_from_base(
        &mut self,
        name: &str,
        base: &str,
    ) -> Result<String, TextEncodingError> {
        let normalized_name = normalize_name(name)?;
        let normalized_base = normalize_name(base)?;
        let base_definition = self
            .encodings
            .get(&normalized_base)
            .cloned()
            .ok_or_else(|| TextEncodingError::UnknownEncoding(base.to_string()))?;
        self.encodings
            .insert(normalized_name.clone(), base_definition);
        Ok(normalized_name)
    }

    pub fn encode_bytes(&self, encoding: &str, input: &[u8]) -> Result<Vec<u8>, TextEncodingError> {
        let normalized = normalize_name(encoding)?;
        let definition = self
            .encodings
            .get(&normalized)
            .ok_or_else(|| TextEncodingError::UnknownEncoding(encoding.to_string()))?;
        definition.encode_bytes(&normalized, input)
    }

    pub fn define_cdef_range(
        &mut self,
        encoding: &str,
        start: u8,
        end: u8,
        coded: u32,
    ) -> Result<(), TextEncodingError> {
        let normalized = normalize_name(encoding)?;
        let definition = self
            .encodings
            .get_mut(&normalized)
            .ok_or_else(|| TextEncodingError::UnknownEncoding(encoding.to_string()))?;
        definition.define_range(&normalized, start, end, coded)
    }

    pub fn define_tdef_increment(
        &mut self,
        encoding: &str,
        chars: &[u8],
        start_value: u32,
    ) -> Result<(), TextEncodingError> {
        let normalized = normalize_name(encoding)?;
        let definition = self
            .encodings
            .get_mut(&normalized)
            .ok_or_else(|| TextEncodingError::UnknownEncoding(encoding.to_string()))?;
        definition.define_tdef_increment(&normalized, chars, start_value)
    }

    pub fn define_tdef_values(
        &mut self,
        encoding: &str,
        chars: &[u8],
        values: &[u8],
    ) -> Result<(), TextEncodingError> {
        let normalized = normalize_name(encoding)?;
        let definition = self
            .encodings
            .get_mut(&normalized)
            .ok_or_else(|| TextEncodingError::UnknownEncoding(encoding.to_string()))?;
        definition.define_tdef_values(&normalized, chars, values)
    }

    pub fn define_edef(
        &mut self,
        encoding: &str,
        pattern: &[u8],
        replacement: &[u8],
    ) -> Result<(), TextEncodingError> {
        let normalized = normalize_name(encoding)?;
        let definition = self
            .encodings
            .get_mut(&normalized)
            .ok_or_else(|| TextEncodingError::UnknownEncoding(encoding.to_string()))?;
        definition.define_escape(&normalized, pattern, replacement)
    }

    fn builtin_ascii() -> EncodingDefinition {
        let mut definition = EncodingDefinition::default();
        for byte in 0u8..=0x7F {
            definition.char_map.insert(byte, byte);
        }
        definition
    }

    fn builtin_petscii() -> EncodingDefinition {
        let mut definition = EncodingDefinition::default();
        for byte in 0u8..=0x7F {
            let mapped = if byte.is_ascii_uppercase() {
                byte | 0x80
            } else if byte.is_ascii_lowercase() {
                byte - 0x20
            } else {
                byte
            };
            definition.char_map.insert(byte, mapped);
        }
        definition
    }
}

fn normalize_name(name: &str) -> Result<String, TextEncodingError> {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(TextEncodingError::InvalidEncodingName);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_names_case_insensitively() {
        let registry = TextEncodingRegistry::new();
        assert_eq!(registry.resolve_name("ascii"), Some("ascii".to_string()));
        assert_eq!(registry.resolve_name("ASCII"), Some("ascii".to_string()));
        assert_eq!(
            registry.resolve_name("petscii"),
            Some("petscii".to_string())
        );
        assert_eq!(
            registry.resolve_name("PeTsCiI"),
            Some("petscii".to_string())
        );
        assert_eq!(registry.resolve_name("unknown"), None);
    }

    #[test]
    fn ensure_encoding_creates_user_encodings() {
        let mut registry = TextEncodingRegistry::new();
        assert_eq!(registry.resolve_name("custom"), None);
        let name = registry.ensure_encoding("custom").expect("create custom");
        assert_eq!(name, "custom");
        assert_eq!(registry.resolve_name("custom"), Some("custom".to_string()));
    }

    #[test]
    fn ascii_encoding_is_identity_for_7bit_bytes() {
        let registry = TextEncodingRegistry::new();
        let input = b"Az09\r\n\t";
        let out = registry
            .encode_bytes("ascii", input)
            .expect("ascii encodes");
        assert_eq!(out, input);
    }

    #[test]
    fn ascii_rejects_non_7bit_bytes() {
        let registry = TextEncodingRegistry::new();
        let err = registry
            .encode_bytes("ascii", &[0x80])
            .expect_err("ascii should reject high-bit bytes");
        assert_eq!(
            err,
            TextEncodingError::MissingCharMapping {
                encoding: "ascii".to_string(),
                byte: 0x80,
            }
        );
    }

    #[test]
    fn petscii_maps_letters_and_preserves_non_letters() {
        let registry = TextEncodingRegistry::new();
        let out = registry
            .encode_bytes("petscii", b"Az09")
            .expect("petscii encodes");
        assert_eq!(out, vec![0xC1, 0x5A, b'0', b'9']);
    }

    #[test]
    fn cdef_tdef_and_edef_build_custom_encoding() {
        let mut registry = TextEncodingRegistry::new();
        registry.ensure_encoding("custom").expect("create custom");
        registry
            .define_cdef_range("custom", b'A', b'Z', 1)
            .expect("cdef");
        registry
            .define_tdef_increment("custom", b"xy", 60)
            .expect("tdef");
        registry
            .define_edef("custom", b"{cr}", &[13])
            .expect("edef");
        let out = registry.encode_bytes("custom", b"A{cr}xy").expect("encode");
        assert_eq!(out, vec![1, 13, 60, 61]);
    }

    #[test]
    fn cdef_rejects_overlapping_ranges() {
        let mut registry = TextEncodingRegistry::new();
        registry.ensure_encoding("custom").expect("create custom");
        registry
            .define_cdef_range("custom", b'A', b'Z', 1)
            .expect("first cdef");
        let err = registry
            .define_cdef_range("custom", b'Z', b'Z', 99)
            .expect_err("overlap should fail");
        assert_eq!(
            err,
            TextEncodingError::CharacterAlreadyDefined {
                encoding: "custom".to_string(),
                byte: b'Z',
            }
        );
    }

    #[test]
    fn ensure_encoding_from_base_clones_source_mapping() {
        let mut registry = TextEncodingRegistry::new();
        registry
            .ensure_encoding_from_base("copy", "petscii")
            .expect("clone petscii");
        let out = registry.encode_bytes("copy", b"Az").expect("encodes");
        assert_eq!(out, vec![0xC1, 0x5A]);
    }
}
