// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Shared token value constants used by the assembler.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenValue {
    None = 0,
    Or = 1,
    Xor = 2,
    And = 3,
    Plus = 4,
    Minus = 5,
    Multiply = 6,
    Divide = 7,
    Mod = 8,
    Shl = 9,
    Shr = 10,
    Name = 11,
    Label = 12,
    Eq = 13,
    Ne = 14,
    Ge = 15,
    Gt = 16,
    Le = 17,
    Lt = 18,
    High = 19,
    Low = 20,
    If = 21,
    Else = 22,
    ElseIf = 23,
    EndIf = 24,
    Switch = 25,
    Case = 26,
    Default = 27,
    EndSwitch = 28,
}
