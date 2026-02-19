# opForge465 C64 Native VM Project Scaffold

This is a multi-file opForge project setup intended to grow into a full native C64 assembler host.

## Files

- `main.asm`: root module, C64 BASIC stub, region/section packing, output config.
- `op465_contract.asm`: frozen control-block offsets, status codes, and ABI constants.
- `op465_data.asm`: runtime state block and sample in-memory payloads.
- `op465_hooks.asm`: host I/O hook entry points for source and `.opcpu` loading.
- `op465_vmcore.asm`: dispatch/handler skeleton and VM algorithm sketch.

## Host hook entry points

Replace these first when integrating real device/filesystem I/O:

- `host_hook_load_opcpu_package`
- `host_hook_open_input_file`
- `host_hook_next_source_line`

## VM growth order

1. Keep `entry_init`, `entry_load_package`, and `entry_set_pipeline` behavior stable.
2. Implement `handle_tokenize` as VM-authoritative.
3. Implement `handle_parse` over portable line envelope output.
4. Implement `handle_encode` and wire emitted bytes to output payload.
5. Expand package parsing beyond the minimal `OPCP` v1 header checks.

## Code size estimate

Planned steady-state code target is about `9.3 KiB (+/- 1.2 KiB)`, plus runtime buffers (`1.5-3 KiB`) and loaded `.opcpu` bytes.

## Build

From repo root:

```bash
cargo run -- -i examples/opthread/c64/opforge465_vm -x build/opforge465-c64-native-bootstrap.hex
```

Expected artifacts:

- `build/opforge465-c64-native-bootstrap.prg`
- `build/opforge465-c64-native-bootstrap.map`
- `build/opforge465-c64-native-bootstrap.hex`
