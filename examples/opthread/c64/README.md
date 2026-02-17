# opThread C64 Native Harness Scaffold

This directory contains a basic opForge-format host harness scaffold that assembles into a C64 PRG:

- `examples/opthread/c64/native6502_harness.asm`

## What it does

- Emits a C64 BASIC stub (`10 SYS 2062`) and machine code body.
- Defines and updates an `OT65` control block layout compatible with the current v1 contract.
- Implements ordinal dispatch stubs for:
1. `init`
2. `load_package`
3. `set_pipeline`
4. `tokenize_line`
5. `parse_line`
6. `encode_instruction`
7. `last_error`
- Runs a tiny in-program scaffold flow:
1. Calls `init`.
2. Calls `set_pipeline` (currently stubbed to runtime error `3`).
3. Calls `last_error`.

Visual result:
- Border color is mapped from the most recent snapshotted status code.
- With current stubs, you should expect `STATUS_RUNTIME_ERROR` (`3`) signaling.

## Build

From repo root:

```bash
cargo run -- -i examples/opthread/c64/native6502_harness.asm -x build/opthread-native6502-harness.hex
```

Outputs:

- `build/opthread-native6502-harness.hex`
- `build/opthread-native6502-harness.prg`
- `build/opthread-native6502-harness.map`

## Run in VICE

```bash
x64sc -autostart build/opthread-native6502-harness.prg
```

## Run on real C64 / Ultimate64

Load and run the PRG normally. The BASIC line autostarts via `SYS 2062`.

## Current status

This is a harness scaffold only. VM-backed handlers for `load_package`, `set_pipeline`, `tokenize_line`, `parse_line`, and `encode_instruction` are intentionally stubbed to runtime error until the native VM implementation lands.
