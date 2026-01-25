# asm485
Intel 8085 Assembler with expressions, directives, and preprocessor macros.

This is an assembler for Intel 8080 and 8085 processors. It is based on a fork of [**asm85** by Tom Nisbet](https://github.com/eriktier/asm85).

It produces an Intel Hex format object file as output.  A separate list file is also created that contains all of the assembled data and opcodes as well as a symbol table.  One or more binary image files can also be created.

Important features of this assembler include expression evaluation for constants and string initialization for data. It supports assembler directives ORG, EQU, DB, DW, DS, END, and CPU, plus preprocessor directives DEFINE, IFDEF, IFNDEF, ELSE, ELSEIF, ENDIF, and INCLUDE. Preprocessor directives accept an optional leading `#` (for example, `#DEFINE` or `DEFINE`).

This is a two-pass assembler.  The first pass creates the symbol table and the second produces the output files.

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

## Usage
Syntax is:

    asm485 [OPTIONS] <FILE>

Arguments:
    FILE                         Input assembly file. Must end with .asm. Output files
                                 are written to the current working directory using the
                                 input filename base (e.g., prog.asm -> prog.lst/prog.hex).

Options:
    -b, --bin <ssss:eeee>        Emit a binary image file for an address range (repeatable).
                                 Each range is 4 hex digits for start/end (e.g., 7eff:7fff).
                                 Produces <base>-ssss.bin and fills missing bytes with FF.
    -g, --go <aaaa>              Set execution start address (4 hex digits). Adds a Start
                                 Segment Address record to the hex output.
    -D, --define <NAME[=VAL]>    Predefine a macro (repeatable). If VAL is omitted, it
                                 defaults to 1.
    -c, --cond-debug             Append conditional state to listing lines.
    -h, --help                   Print help.
    -V, --version                Print version.

The `-b` option creates one or more binary image files. The `ssss` and `eeee` arguments are hexadecimal start and end addresses, respectively, and must be 4 hex digits, using leading zeroes if the address is less than `0x1000`.

The `-g` option adds a Start Segment Address record to the output hex file. Some loaders may use this to start execution when the download is complete.

If `test.asm` is specified as the input, new files `test.lst` and `test.hex` will be created for the listing and hex records.

If one or more `-b` options are specified, the output files will be named `test-ssss.bin` for each address range. Bytes not present in the assembly source will be initialized to `FF` in the binary image files.

### Examples
    asm485 test02.asm
creates test02.lst and test02.hex.


    asm485 -b 7eff:7fff -b f000:ffff prog.asm
creates:
* The assembler listing in prog.lst
* The hex records in prog.hex
* A 512 byte binary image file prog-7eff.bin
* A 4096 byte binary image file prog-f000.bin
