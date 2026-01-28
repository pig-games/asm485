# asm485
Intel 8085 Assembler with expressions, directives, and preprocessor macros.

This is an assembler for 8080 Family processors (currently 8080, 8085 and z80) and MOS 6502 Family
(currently 6502 and 65c02) processors.
It was originally based on a fork of [**asm85** by Tom Nisbet](https://github.com/eriktier/asm85).
It is now more inspired by [64tass](https://tass64.sourceforge.net) in terms of features and notational style.
It produces optional Intel Hex, listing, and binary image outputs, selected by command-line arguments.

For all documentation on features and syntax read: [asm485 Reference Manual](docs/asm485-reference-manual.md).

For detailed information about the multi-cpu architecture of the assembler read:
- [Multi Cpu Architecture](docs/multi-cpu-architecture.md).
- [Instruction Table Architecture](docs/instruction-table-architecture.md).


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

    asm485 [ARGUMENTS]

Arguments:

    -i, --infile <FILE>          Input assembly file (repeatable). Must end with .asm.

    -l, --list [FILE]            Emit a listing file. FILE is optional; when omitted, the
                                 output base is used and a .lst extension is added.
                                 
    -x, --hex [FILE]             Emit an Intel Hex file. FILE is optional; when omitted,
                                 the output base is used and a .hex extension is added.
                                 
    -o, --outfile <BASE>         Output filename base when -l/-x are used without a filename.
                                 Also used for -b outputs that omit a filename. Defaults to the
                                 input filename base.
    -b, --bin [FILE:ssss:eeee|ssss:eeee]
                                 Emit a binary image file (repeatable). A range is required.
                                 Use ssss:eeee to use the output base, or FILE:ssss:eeee to
                                 override the filename. If FILE has no extension, .bin is added.
                                 If multiple -b ranges are provided without filenames, each file
                                 is named <base>-ssss.bin to avoid collisions.
    -g, --go <aaaa>              Set execution start address (4 hex digits). Adds a Start
                                 Segment Address record to the hex output. Requires -x/--hex.
    -f, --fill <hh>              Fill byte for -b output (2 hex digits). Defaults to FF.
    -D, --define <NAME[=VAL]>    Predefine a macro (repeatable). If VAL is omitted, it
                                 defaults to 1.
    -c, --cond-debug             Append conditional state to listing lines.
    -h, --help                   Print help.
    -V, --version                Print version.

At least one output option (`-l`, `-x`, or `-b`) is required.

The `-g` option adds a Start Segment Address record to the output hex file. Some loaders may use this to start execution when the download is complete.

If `test.asm` is specified as the input with `-i` and `-l`/`-x` are used without filenames (and `-o` is not used), the outputs will be named `test.lst` and `test.hex`. Bytes not present in the assembly source are initialized to `FF` in binary image files.

When multiple inputs are provided, `-o` must be a directory and explicit output filenames are not allowed; each input uses its own base name under the output directory.

### Examples
    asm485 -l -x -i test02.asm
creates test02.lst and test02.hex.

    asm485 -l -x -b 7eff:7fff -b f000:ffff -i prog.asm
creates:
* The assembler listing in prog.lst
* The hex records in prog.hex
* A 512 byte binary image file prog-7eff.bin
* A 4096 byte binary image file prog-f000.bin

    asm485 -o build/out -l -x -i prog.asm
creates:
* The assembler listing in build/out.lst
* The hex records in build/out.hex

    asm485 -b out.bin:8000:8fff -i prog.asm
creates:
* A 4096 byte binary image file out.bin
