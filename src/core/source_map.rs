// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

//! Source map support for mapping expanded assembler lines back to origin files.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceOrigin {
    pub file: Option<String>,
    pub line: u32,
}

impl SourceOrigin {
    pub fn new(file: Option<String>, line: u32) -> Self {
        Self { file, line }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceMap {
    origins: Vec<SourceOrigin>,
}

impl SourceMap {
    pub fn new(origins: Vec<SourceOrigin>) -> Self {
        Self { origins }
    }

    pub fn origins(&self) -> &[SourceOrigin] {
        &self.origins
    }

    pub fn origin_for_line(&self, line: u32) -> Option<&SourceOrigin> {
        if line == 0 {
            return None;
        }
        self.origins.get(line as usize - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_map_resolves_one_based_lines() {
        let map = SourceMap::new(vec![
            SourceOrigin::new(Some("a.asm".to_string()), 10),
            SourceOrigin::new(Some("b.asm".to_string()), 20),
        ]);

        assert_eq!(
            map.origin_for_line(1).and_then(|o| o.file.as_deref()),
            Some("a.asm")
        );
        assert_eq!(map.origin_for_line(2).map(|o| o.line), Some(20));
        assert!(map.origin_for_line(0).is_none());
        assert!(map.origin_for_line(3).is_none());
    }
}
