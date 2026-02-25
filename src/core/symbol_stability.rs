// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

/// Returns whether a symbol should be treated as unstable for sizing/encoding.
///
/// A symbol is unstable if it is undefined, or if we're in pass 2+ and the
/// symbol exists but is explicitly marked as not finalized.
pub fn is_symbol_unstable(
    symbol_name: &str,
    pass: u8,
    has_symbol: impl Fn(&str) -> bool,
    is_finalized: impl Fn(&str) -> Option<bool>,
) -> bool {
    if !has_symbol(symbol_name) {
        return true;
    }
    pass > 1 && matches!(is_finalized(symbol_name), Some(false))
}

#[cfg(test)]
mod tests {
    use super::is_symbol_unstable;

    #[test]
    fn undefined_symbol_is_unstable() {
        let unstable = is_symbol_unstable("missing", 1, |_name| false, |_name| None);
        assert!(unstable);
    }

    #[test]
    fn non_finalized_symbol_is_unstable_after_pass1() {
        let unstable = is_symbol_unstable("label", 2, |_name| true, |_name| Some(false));
        assert!(unstable);
    }

    #[test]
    fn finalized_symbol_is_stable() {
        let unstable = is_symbol_unstable("label", 2, |_name| true, |_name| Some(true));
        assert!(!unstable);
    }
}
