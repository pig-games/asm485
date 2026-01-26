# asm485 Reference Manual

This document describes the asm485 assembler language, directives, and tooling.
It follows a chapter layout similar to 64tass, but the content is specific to
asm485 and 8080/8085 assembly. Sections marked **Planned** describe features
that are not implemented yet.

## 1. Introduction

asm485 is a two-pass assembler for Intel 8080/8085 code. It supports:
- Dot-prefixed directives and conditionals.
- A 64tass-inspired expression syntax (operators, precedence, ternary).
- Preprocessor directives for includes and conditional compilation.
- Macro expansion with `.macro` and `.segment`.
- Optional listing, Intel HEX, and binary outputs.

The `.cpu` directive currently accepts `8080` and `8085`. Support for Z80 and
related CPUs is planned.

## 2. Usage tips

- Directives, preprocessor directives, and conditionals are dot-prefixed
  (`.org`, `.if`, `.ifdef`).
- `#` is reserved for macro invocation.
- Labels may end with `:` or omit it.
- The program counter can be set with `* = expr` or `.org expr`.
- At least one output option (`-l`, `-x`, `-b`) is required on the command line.

## 3. Expressions and data types

### 3.1 Integers

Integer literals are supported in several formats:
- Decimal: `123`
- Hex: `$1234` or `1234h`
- Binary: `%1010` or `1010b`
- Octal: `17o` or `17q`

Underscores are allowed for readability (`$12_34`).

`$` evaluates to the current address.

### 3.2 Strings

Strings are quoted with `'` or `"` and are usable in data directives:

```
.byte "HELLO", 0
```

### 3.3 Booleans

Logical operators treat non-zero as true. Logical operators return `0` or `1`.

### 3.4 Symbols

Symbols are names bound to values. A symbol can be defined by a label
(current address) or an assignment.

### 3.5 Expressions

Expressions are used in directives and operands. Unary `<` and `>` select the
low or high byte of a value:

```
<($1234+1)
>($1234+1)
```

### 3.6 Expression operators

Operator set (highest level summary):

```
**  *  /  %  +  -  <<  >>  ==  !=  <>  <  <=  >  >=  &  ^  |  &&  ^^  ||  !  ~
?:
```

Concatenation uses `..`.

### 3.7 Conditional operator

The ternary operator `?:` is supported with standard precedence rules:

```
flag ? value_if_true : value_if_false
```

### 3.8 Planned data types

Planned (not implemented yet): bit strings, floating-point values, lists,
tuples, code blocks, and type values.

## 4. Compiler directives

### 4.1 Assembling source

```
.include "file"
```

### 4.2 Controlling the program counter

```
.org $1000
* = $2000
```

### 4.3 Data directives

```
.byte expr[, expr...]
.word expr[, expr...]
.ds expr
```

### 4.4 Symbols and assignments

```
WIDTH = 40          ; read-only constant
var1  := 1          ; read/write variable
var2  :?= 5         ; only if undefined
var1  += 1          ; compound assignment
```

Compound assignment operators:

```
+= -= *= /= %= **= |= ^= &= ||= &&= <<= >>= ..= <?= >?= x= .=
```

`.const` and `.var` mirror `=` and `:=` semantics; `.set` is an alias for `.var`.

### 4.5 Conditional assembly

```
.if expr
.elseif expr
.else
.endif
```

### 4.6 Scopes

Scopes are introduced by `.block` and closed by `.endblock`:

```
OUTER .block
INNER .block
VAL   .const 5
.endblock
.endblock

.word OUTER.INNER.VAL
```

Symbol lookup searches the current scope first, then parent scopes, then global.

### 4.7 Target CPU

```
.cpu 8080
.cpu 8085
```

Planned: `.cpu z80` and other related CPUs.

### 4.8 End of assembly

```
.end
```

### 4.9 Preprocessor directives

Preprocessor directives are dot-prefixed:

```
.ifdef NAME
.ifndef NAME
.elseif NAME
.else
.endif
.include "file"
```

Notes:
- `#` is reserved for macro invocation.
- Preprocessor directives run before macro expansion.
- Preprocessor symbols are provided via the `-D/--define` command-line option.

## 5. Pseudo instructions

### 5.1 Macros

```
NAME .macro a, b=2
    .byte \a, \b
.endmacro
```

Invoke with `#NAME` or `.NAME`:

```
#NAME 1
```

### 5.2 Macro parameters

- Positional: `\1` .. `\9`
- Named: `\name` or `\{name}`
- Full argument list: `\@`
- Text form: `@1` .. `@9`

### 5.3 Segment macros

`.segment` defines a macro that expands inline without an implicit
`.block/.endblock` wrapper:

```
INLINE .segment v
    .byte \v
.endsegment

.INLINE 7
```

### 5.4 Repetition

Planned (not implemented yet): repeat/loop-style directives.

## 6. Compatibility

- Dot-prefixed directives are required (for `.org`, `.set`, `.if`, etc.).
- `#` is reserved for macro invocation.
- Labels may omit the trailing `:`.

## 7. Command line options

Syntax:

```
asm485 [OPTIONS]
```

Inputs:
- `-i, --infile <FILE>`: input `.asm` file (repeatable).

Outputs (at least one required):
- `-l, --list [FILE]`: listing output (optional filename).
- `-x, --hex [FILE]`: Intel HEX output (optional filename).
- `-b, --bin [FILE:ssss:eeee|ssss:eeee]`: binary image with range(s).

Other options:
- `-o, --outfile <BASE>`: output base name if output filename omitted.
- `-f, --fill <hh>`: fill byte for binary output (hex).
- `-g, --go <aaaa>`: execution start address in HEX output.
- `-D, --define <NAME[=VAL]>`: predefine macro (repeatable).
- `-c, --cond-debug`: include conditional state in listing.

Notes:
- If multiple inputs are provided, `-o` must be a directory and explicit output
  filenames are not allowed; each input uses its own base name under the output
  directory.

## 8. Messages

Diagnostics include a line/column and a highlighted span in listings. Terminal
output may use ANSI colors to highlight the offending region.

## 9. Credits

asm485 is derived from the asm85 assembler by Tom Nisbet and has been extended
with new expression syntax, directives, and tooling.

## 10. Default translation

Planned (not implemented yet): translation tables for character/byte mappings.

## 11. Escapes

Strings accept the following escapes:

```
\n  \r  \t  \0  \xHH
```

Any other escape sequence inserts the escaped character as-is.

## 12. Opcodes

Instruction mnemonics are 8080/8085 compatible. `.cpu` is intended to select
additional opcode sets in the future (e.g. Z80).

## 13. Appendix: quick reference

### 13.1 Directives

```
.org  .const  .var  .set  .byte  .word  .ds  .end  .cpu
.block  .endblock
.macro  .endmacro  .segment  .endsegment
.if  .elseif  .else  .endif
.ifdef  .ifndef  .include
```

### 13.2 Assignment operators

```
=  :=  :?=  +=  -=  *=  /=  %=  **=  |=  ^=  &=  ||=  &&=  <<=  >>=  ..=  <?=  >?=  x=  .=
```
