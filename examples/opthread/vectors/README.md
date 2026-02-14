# opThread `.optst` parity vectors (v0.1 draft)

These vectors are used by the `opthread-parity` smoke workflow to pin pilot-family behavior.

Fields:

- `family`: family id
- `cpu`: cpu id
- `dialect`: expected resolved dialect id
- `native_line`: source line assembled through native path
- `canonical_line`: canonical-equivalent line used as package-path parity baseline
- `expect_status`: `ok` or `error`

The format is line-oriented `key=value` pairs.
