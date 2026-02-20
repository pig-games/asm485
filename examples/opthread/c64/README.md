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
2. Calls `load_package` with a sample in-memory `OPCP` header (magic/version/endian checks).
3. Calls `set_pipeline` with wire payload `m6502\0`.
4. Calls `last_error`.

Visual result:
- Border color is mapped from the most recent snapshotted status code.
- For the default scaffold flow, you should expect `STATUS_OK` (`0`) signaling.

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

This is still a harness scaffold. `load_package` validates control-block pointer/length and the minimal package header (`OPCP`, version `0x0001`, endian marker `0x1234`) and persists loaded-package state. `set_pipeline` now validates loaded-package preconditions and payload shape (`cpu_id\0dialect`), and currently accepts only `m6502` with no dialect suffix. `tokenize_line`, `parse_line`, and `encode_instruction` remain runtime-error stubs until native VM handlers land.

