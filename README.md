# asm485
Intel 8085 Assembler with expressions, directives, and preprocessor macros.

This is an assembler for Intel 8080 and 8085 processors. It is based on a fork of [**asm85** by Tom Nisbet](https://github.com/eriktier/asm85).

It produces optional Intel Hex, listing, and binary image outputs, selected by command-line arguments.

Important features of this assembler include expression evaluation for constants and string initialization for data. It supports assembler directives .org, .const, .var (with .set as an alias), .byte, .word, .ds, .end, .cpu, macro directives .macro/.endmacro, and scope directives .block/.endblock. You can also set the program counter with `* = expr`. Preprocessor directives are .IFDEF, .IFNDEF, .ELSE, .ELSEIF, .ENDIF, and .INCLUDE. Assembler conditionals use `.if/.elseif/.else/.endif` (expression-based). Preprocessor directives use a leading `.`; `#` is reserved for macro invocation. Preprocessor symbols are provided via the `-D/--define` option.

Expression syntax follows a 64tass-style operator set: `+ - * / % ** << >> == != <> < <= > >= & ^ | && ^^ || ! ~` plus unary `<`/`>` for low/high byte and ternary `?:`. Non-zero values are TRUE; logical operators return `1` or `0`.
Scopes are introduced with `.block`/`.endblock`. A label before `.block` names the scope, and scoped symbols can be referenced with `scope.symbol`. Unqualified symbols resolve from the innermost scope out to global.

Macros are defined with `name .macro [params]` and closed with `.endmacro` (or `.endm`). Invoke macros with `#name` or `.name`. Parameter references use `\\1`..`\\9`, named params via `\\name` (or `\\{name}`), full list via `\\@`, and text refs via `@1`..`@9`. `.segment`/`.endsegment` defines a macro that expands inline without an implicit `.block`/`.endblock`.

This is a two-pass assembler.  The first pass creates the symbol table and the second produces the output files.

Symbol assignment (colon optional):
    WIDTH = 40          ; read-only constant (like .const)
    var1 := 1           ; read/write variable (like .var)
    var2 :?= 5          ; assign only if undefined
    var1 += 1           ; compound assignment (add)

Compound assignment operators: `+= -= *= /= %= **= |= ^= &= ||= &&= <<= >>= ..= <?= >?= x= .=`

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

    asm485 [OPTIONS]

Arguments:
    -i, --infile <FILE>          Input assembly file (repeatable). Must end with .asm.

Options:
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
