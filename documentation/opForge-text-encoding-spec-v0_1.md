# opForge Text Encoding Specification (v0.2)

Date: 2026-02-12

## Summary

This spec defines opForge text encoding behavior for:

- built-in encodings (`ascii`, `petscii`)
- user-defined in-source encodings via 64tass-style directives
- text emission in `.byte/.db`, `.text`, `.null`, `.ptext`

Reference model: 64tass encoding directives ([`.enc/.encode/.cdef/.tdef/.edef`](https://tass64.sourceforge.net/#d_enc)).

## Design Position

- Keep opForge's unified data model: string operands in `.byte/.db` are encoding-aware.
- Keep `.text/.null/.ptext` as convenience directives, not a separate encoding subsystem.
- Adopt 64tass-like in-source encoding definition directives with opForge-native parser forms.

This preserves opForge ergonomics while making source-porting from 64tass practical.

## User-Facing Behavior

## 1. Active encoding selection

```asm
.encoding <name>
.enc <name>                    ; alias
```

- `<name>`: identifier, number token, register token, or string token resolved as text.
- Matching is case-insensitive.
- Unknown name is an error with known encoding names in the diagnostic.

Built-ins:

- `ascii` (default)
- `petscii`

Scope:

- Active encoding is module-scoped.
- On `.module`, active encoding resets to `ascii`.

## 2. Encoding definition scope

```asm
.encode <name>[, <base>]
.endencode
```

- `.encode` opens an encoding-definition scope.
- Inside the scope, the selected encoding becomes active.
- `.endencode` restores the previously active encoding.
- `.endencode` without `.encode` is an error.
- Closing a module with an open `.encode` scope is an error.

Creation semantics:

- `.encode <name>`: create empty encoding if missing; otherwise reopen existing encoding.
- `.encode <name>, <base>`: clone `<base>` into `<name>` (overwrite/reinitialize target definition).

## 3. Definition directives (inside `.encode` only)

```asm
.cdef <start>, <end>, <value>
.tdef <chars>, <value[, value...]>
.edef <pattern>, <replacement[, replacement...]>
```

### `.cdef`

- `<start>` and `<end>` are source bytes (single-byte string literal or byte expression).
- `<value>` is first output byte value.
- Maps inclusive source range to ascending output bytes.
- Errors on invalid range (`start > end`), output overflow (`> $FF`), or duplicate source definition.

### `.tdef`

- `<chars>` must be a string literal; each source byte from that literal is mapped.
- Two forms:
  - Increment form: `.tdef "abc", 32` maps `a->32`, `b->33`, `c->34`.
  - Explicit form: `.tdef "abc", 1, 2, 3` maps per value list.
- Errors on count mismatch (explicit form), byte overflow, or duplicate source definition.

### `.edef`

- `<pattern>` must be a string literal.
- Replacement operands can be byte expressions and/or string literals (string bytes appended raw).
- Escape substitutions are applied before char-map lookup.
- Matching rule: longest matching escape at the current position wins.
- Empty pattern is an error.

## 4. Emission behavior

### `.byte/.db`

- Numeric operands: unchanged.
- String operands: encoded with active encoding.

### `.text`

- Emits encoded bytes for one or more string operands.

### `.null`

- Emits encoded bytes for one string operand, then terminator byte `0`.
- Strict rule (64tass-aligned): error if encoded input already contains `0`.

### `.ptext`

- Emits length byte (`0..255`) then encoded bytes for one string operand.
- Error when encoded length exceeds `255`.

## 5. String expressions

String expressions are encoded before folding:

- 1-byte string => scalar byte value
- 2-byte string => `(first << 8) | second`
- >2 bytes => expression error

## 6. Encoding algorithm

For each input string:

1. Try `.edef` substitutions at current position.
2. If escape matched, emit replacement bytes and advance by pattern length.
3. Otherwise map source byte through char-map (`.cdef/.tdef`/built-in table).
4. Missing source mapping is an error.

## 7. Diagnostics

Required diagnostics include:

- unknown encoding name
- missing source mapping for a byte in active encoding
- duplicate source-byte definition
- invalid `.cdef` range
- overflow values (`> $FF`)
- `.tdef` count mismatch
- empty `.edef` pattern
- `.cdef/.tdef/.edef` outside `.encode`
- `.endencode` without matching `.encode`
- `.endmodule` with open `.encode`
- `.null` encoded-input contains zero byte
- `.ptext` encoded length overflow

## 8. 64tass Compatibility Notes

Aligned with 64tass direction:

- `.enc` selection model
- `.encode/.endencode` scoped definition workflow
- `.cdef/.tdef/.edef` style mapping directives
- strict `.null` zero-byte rule

Intentional opForge divergence:

- `.byte` string operands are encoding-aware (not split from `.text`).
- No external encoding-table file form in this version.

## Core Architecture Fit

Text encoding is CPU-agnostic assembler core behavior.

Primary implementation areas:

- `src/core/text_encoding.rs`
- `src/assembler/mod.rs`
- `src/assembler/asmline_directives.rs`

## Implementation Plan (v0.2)

1. Core registry and tables:
- dynamic encoding registry by name
- built-ins (`ascii`, `petscii`)
- `.cdef/.tdef/.edef` definition APIs

2. Assembler state and scope:
- active encoding by name
- `.encode` scope stack with active-encoding restore
- module reset and unclosed-scope checks

3. Directive wiring:
- `.encoding/.enc`
- `.encode/.endencode`
- `.cdef/.tdef/.edef`
- `.text/.null/.ptext`

4. Emission/eval integration:
- `.byte/.db` string encoding
- string-expression folding via active encoding

5. Validation and docs:
- unit tests for definition directives and errors
- examples + reference outputs for definition workflow
- manual updates for syntax and quick reference

## Future Extensions

- External encoding tables (`.enc file,offset` style)
- Additional built-in encodings
- Optional helpers for wider length-prefixed text forms
