# opForge
Multi-target Assembler with expressions, directives, and preprocessor macros. It also supports modules. Not 
plain old #include (it has that also) but true modules, with visibility control. No ifdefs to prevent multiple
includes needed :).

This is an multi-target assembler for 8080 Family processors (currently 8080, 8085 and z80) and MOS 6502 Family
(currently 6502 and 65c02) processors.

It is partly inspired by [64tass](https://tass64.sourceforge.net) in terms of features and notational style.
It produces optional Intel Hex, listing, and binary image outputs, selected by command-line arguments.

It also supports patterned `.statement` definitions for custom statement syntax, with typed captures using
`type:name` and quoted literal commas (use `","`). Statement labels may include dots (e.g. `move.b`).

For all documentation on features and syntax read: [opForge Reference Manual](documentation/opForge-reference-manual.md).


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

Rebuild reference outputs (updates examples/reference/*.lst and *.hex):

    make reference

The reference set includes additional examples to exercise the newer syntax
(dot-prefixed conditionals, preprocessor directives, and 64tass-style
expressions).

## Usage
Syntax is:

    opForge [ARGUMENTS]

Arguments:

    -i, --infile <FILE|FOLDER>   Input assembly file or folder (repeatable). Files must end with .asm.
                                Folder inputs must contain exactly one main.* root module.

    -l, --list [FILE]            Emit a listing file. FILE is optional; when omitted, the
                                 output base is used and a .lst extension is added.
                                 
    -x, --hex [FILE]             Emit an Intel Hex file. FILE is optional; when omitted,
                                 the output base is used and a .hex extension is added.
                                 
    -o, --outfile <BASE>         Output filename base when -l/-x are used without a filename.
                                 Also used for -b outputs that omit a filename. Defaults to the
                                 input filename base.
    -b, --bin [FILE:ssss:eeee|ssss:eeee|FILE]
                                 Emit a binary image file (repeatable). A range is optional.
                                 Use ssss:eeee to use the output base, FILE:ssss:eeee to
                                 override the filename, or FILE to emit the full output range.
                                 If FILE has no extension, .bin is added.
                                 If multiple -b ranges are provided without filenames, each file
                                 is named <base>-ssss.bin to avoid collisions.
    -g, --go <aaaa>              Set execution start address (4 hex digits). Adds a Start
                                 Segment Address record to the hex output. Requires hex output.
    -f, --fill <hh>              Fill byte for binary output (2 hex digits). Defaults to FF.
    -D, --define <NAME[=VAL]>    Predefine a macro (repeatable). If VAL is omitted, it
                                 defaults to 1.
    -c, --cond-debug             Append conditional state to listing lines.
    -h, --help                   Print help.
    -V, --version                Print version.

At least one output option (`-l`, `-x`, or `-b`) is required unless a single input provides
a root-module output name (via `.meta.output.name`) or `-o` is specified. Output selection can
also be provided by `.meta.output.list`, `.meta.output.hex`, and `.meta.output.bin` in the root module;
`.meta.output.fill` sets the binary fill byte. CLI flags always take precedence when both are present.

The `-g` option adds a Start Segment Address record to the output hex file. Some loaders may use this to start execution when the download is complete.

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

## Linker Regions Workflow (v3.1)

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

