# opForge
Multi-target assembler with expressions, directives, and preprocessor macros. It also supports true modules
with visibility control alongside textual includes (`.include`).

This is a multi-target assembler for Intel 8080 family processors (currently 8080, 8085, and Z80) and MOS 6502
family processors (currently 6502, 65C02, and 65816).

It is partly inspired by [64tass](https://tass64.sourceforge.net) in terms of features and notational style.
It produces optional Intel Hex, listing, and binary image outputs selected by command-line arguments.
For single-input builds, opForge can default to list+hex output when an output base is available
(`.meta.output.name` or `-o`).

It also supports patterned `.statement` definitions for custom statement syntax, with typed captures using
`type:name` and quoted literal commas (use `","`). Statement labels may include dots (e.g. `move.b`).

For full documentation on features and syntax, read the [opForge Reference Manual](documentation/opForge-reference-manual.md).
For VM host/boundary semantics, see [VM Boundary & Protocol Specification (v1)](documentation/vm-boundary-protocol-v1.md).
For version-specific 65816 implementation scope and limits, see [RELEASE_NOTES_v0.9.3.md](RELEASE_NOTES_v0.9.3.md).

Build:

    make
    # or: make build

Run:

    cargo run -- <args>

Release build:

    make release

Compare Rust outputs with references:

    make reference-test

Run the full test suite:

    make test

Run VM parity smoke checks (optional feature lane):

    make test-vm-parity

Run MOS6502 runtime/package parity checks:

    make test-vm-runtime

Run MOS6502 runtime/package artifact-mode checks (optional feature lane):

    make test-vm-runtime-artifact

Run Intel8080-family runtime/package parity checks:

    make test-vm-runtime-intel

Run rollout policy/criteria gate checks:

    make test-vm-rollout-criteria

Run the local MOS6502 CI gate bundle:

    make ci-vm-mos6502

Run the local Intel8080-family CI gate bundle:

    make ci-vm-intel8080

VM rollout status (VM runtime is default):
- Authoritative package-runtime family: `mos6502` (`m6502`, `65c02`, `65816`).
- Authoritative package-runtime family: `intel8080` (`8085`, `z80`).

Optional on-disk runtime package artifact mode:
- Enable feature `vm-runtime-opcpu-artifact`.
- Runtime then loads/writes `.opcpu` bytes at `target/vm/opforge-vm-runtime.opcpu` with registry-build fallback.
- Rust-table-driven package generation remains the supported authoring path for new families/CPUs (`build_hierarchy_package_from_registry`).

Cargo feature flags:
- `vm-runtime-opcpu-artifact`: enables on-disk runtime package artifact mode (`target/vm/opforge-vm-runtime.opcpu`) with registry fallback.
- `vm-parity`: enables parity-focused VM test lanes and CI checks.

Rebuild reference outputs (updates examples/reference/*.lst and *.hex):

    make reference

The reference set includes additional examples to exercise the newer syntax
(dot-prefixed conditionals, preprocessor directives, and 64tass-style
expressions).

## Usage
Syntax is:

    opForge [OPTIONS] [INPUT]...

Arguments:

    [INPUT]...                    Optional migration-friendly positional input.
                                 Exactly one positional INPUT is accepted and
                                 treated like -i INPUT. Multiple positional
                                 inputs require explicit -i/--infile.

    -i, --infile <FILE|FOLDER>   Input assembly file or folder (repeatable). Files must end with .asm.
                                Folder inputs must contain exactly one main.* root module.

    -I, --include-path <DIR>     Additional include search root (repeatable).
                                 Include resolution order is: including file
                                 directory, then include roots in command-line
                                 order.

    -M, --module-path <DIR>      Additional module search root (repeatable).
                                 Module roots are searched in this order: input
                                 root directory, then module roots in
                                 command-line order.

    -l, --list [FILE]            Emit a listing file. FILE is optional; when omitted, the
                                 output base is used and a .lst extension is added.
                                 
    -x, --hex [FILE]             Emit an Intel Hex file. FILE is optional; when omitted,
                                 the output base is used and a .hex extension is added.
                                 
    -o, --outfile <BASE>         Output filename base when -l/-x are used without a filename.
                                 Also used for -b outputs that omit a filename. Defaults to the
                                 input filename base.
    --dependencies <FILE>        Write Makefile-compatible dependency rules to FILE.
    --dependencies-append        Append dependency rules to --dependencies FILE.
    --make-phony                 Emit phony targets for each dependency path in generated dependency output.
    --labels <FILE>              Write assembled symbol labels to FILE.
    --vice-labels                Write --labels output in VICE-compatible format.
    --ctags-labels               Write --labels output in ctags-compatible format.
    -b, --bin [FILE:ssss:eeee|ssss:eeee|FILE]
                                 Emit a binary image file (repeatable). A range is optional.
                                 Use ssss:eeee to use the output base, FILE:ssss:eeee to
                                 override the filename, or FILE to emit the full output range.
                                 Range values are 4-8 hex digits per side.
                                 If FILE has no extension, .bin is added.
                                 If multiple -b ranges are provided without filenames, each file
                                 is named <base>-ssss.bin to avoid collisions.
    -g, --go <aaaa>              Set execution start address (4-8 hex digits). Adds a Start
                                 Address record to the hex output. Requires hex output.
    -f, --fill <hh>              Fill byte for binary output (2 hex digits). Defaults to FF.
    -D, --define <NAME[=VAL]>    Predefine a macro (repeatable). If VAL is omitted, it
                                 defaults to 1.
    -c, --cond-debug             Append conditional state to listing lines.
    --line-numbers               Compatibility flag for listing line-number column (enabled by default).
    --tab-size <N>               Expand tab characters in listing source text using N spaces.
    --verbose-list               Compatibility flag reserved for expanded listing sections.
    -q, --quiet                  Suppress diagnostics for successful runs.
    -E, --error <FILE>           Write diagnostics to FILE instead of stderr.
    --error-append               Append diagnostics to --error FILE.
    --no-error                   Disable diagnostic output routing.
    -w, --no-warn                Suppress warning diagnostics.
    --Wall                       Enable all warning classes (reserved for future groups).
    --Werror                     Treat warnings as errors.
    --format <text|json>         Select global CLI output format.
    --diagnostics-style <classic|rustc>
                                 Select text diagnostics rendering style (default: rustc).
    --fixits-dry-run             Plan machine-applicable fixits without writing files.
    --apply-fixits               Apply machine-applicable fixits.
    --fixits-output <FILE>       Write fixit planning/apply report JSON to FILE.
    --cpu <ID>                   Set initial CPU before parsing source directives.
    --print-capabilities         Print deterministic capability metadata and exit.
    --print-cpusupport           Print deterministic CPU support metadata and exit.
    --pp-macro-depth <N>         Maximum preprocessor macro expansion depth (default 64, minimum 1).
    --input-asm-ext <EXT>        Additional accepted source-file extension for direct file inputs.
    --input-inc-ext <EXT>        Additional accepted root-module extension for folder inputs.
    -h, --help                   Print help.
    -V, --version                Print version.

For multiple inputs, at least one output option (`-l`, `-x`, or `-b`) must be selected.
For a single input with no explicit outputs, opForge defaults to list+hex when an output base is
available from `.meta.output.name` or `-o`; otherwise output selection is required. Output selection can
also be provided by `.meta.output.list`, `.meta.output.hex`, and `.meta.output.bin` in the root module;
`.meta.output.fill` sets the binary fill byte. CLI flags always take precedence when both are present.

The `-g` option adds a Start Segment Address record for 16-bit values and a Start Linear
Address record for wider values in the output hex file.

If `test.asm` is specified as the input with `-i` and `-l`/`-x` are used without filenames (and `-o` is not used), the outputs will be named `test.lst` and `test.hex`. Bytes not present in the assembly source are initialized to `FF` in binary image files.

When multiple inputs are provided, `-o` must be a directory and explicit output filenames are not allowed; each input uses its own base name under the output directory.

### Examples
    opForge -l -x -i test02.asm
creates test02.lst and test02.hex.

    opForge -l -x -b 7eff:7fff -b f000:ffff -i prog.asm
creates:
* The assembler listing in prog.lst
* The hex records in prog.hex
* A 512 byte binary image file prog-7eff.bin
* A 4096 byte binary image file prog-f000.bin

    opForge -o build/out -l -x -i prog.asm
creates:
* The assembler listing in build/out.lst
* The hex records in build/out.hex

    opForge -b out.bin:8000:8fff -i prog.asm
creates:
* A 4096 byte binary image file out.bin

    opForge -b -i prog.asm
creates:
* A binary image file containing the emitted output range

    opForge -x -g 123456 -b out.bin:123400:12341f -i examples/65816_wide_image.asm
creates:
* A hex file with wide-address records (ELA + start linear address)
* A binary image file out.bin covering `$123400..$12341F`

## Linker Regions Workflow

Use explicit region placement and output directives for section-based builds.

Minimal flow:

```asm
.module main

.region ram, $1000, $10ff

.section code
start:
    .byte $42, $43
.endsection

.place code in ram

.output "build/minimal.bin", format=bin, sections=code
.mapfile "build/minimal.map", symbols=public
.exportsections dir="build/minimal_sections", format=bin

.endmodule
```

Grouped placement flow:

```asm
.pack in rom : code, data, zero
.output "build/full.prg", format=prg, contiguous=false, sections=code,data
.output "build/full-image.bin", format=bin, image="$8000..$8010", fill=$ff, contiguous=false, sections=code,data
```

Examples:
- `examples/linker_regions_minimal.asm`
- `examples/linker_regions_full.asm`

### Diagnostic + Fixit Examples

Directive typo diagnostics with machine-applicable fixits:
- [examples/directive_typo_endif_fixit_error.asm](examples/directive_typo_endif_fixit_error.asm) → [examples/reference/directive_typo_endif_fixit_error.err](examples/reference/directive_typo_endif_fixit_error.err)
- [examples/directive_typo_elseif_fixit_error.asm](examples/directive_typo_elseif_fixit_error.asm) → [examples/reference/directive_typo_elseif_fixit_error.err](examples/reference/directive_typo_elseif_fixit_error.err)
- [examples/directive_typo_endmodule_fixit_error.asm](examples/directive_typo_endmodule_fixit_error.asm) → [examples/reference/directive_typo_endmodule_fixit_error.err](examples/reference/directive_typo_endmodule_fixit_error.err)
- [examples/directive_typo_endsection_fixit_error.asm](examples/directive_typo_endsection_fixit_error.asm) → [examples/reference/directive_typo_endsection_fixit_error.err](examples/reference/directive_typo_endsection_fixit_error.err)
- [examples/directive_typo_endmatch_fixit_error.asm](examples/directive_typo_endmatch_fixit_error.asm) → [examples/reference/directive_typo_endmatch_fixit_error.err](examples/reference/directive_typo_endmatch_fixit_error.err)

Dialect-oriented diagnostics with mnemonic replacement suggestions:
- [examples/dialect_mnemonic_fixit_error.asm](examples/dialect_mnemonic_fixit_error.asm) → [examples/reference/dialect_mnemonic_fixit_error.err](examples/reference/dialect_mnemonic_fixit_error.err)
- [examples/dialect_parser_fixit_error.asm](examples/dialect_parser_fixit_error.asm) → [examples/reference/dialect_parser_fixit_error.err](examples/reference/dialect_parser_fixit_error.err)
