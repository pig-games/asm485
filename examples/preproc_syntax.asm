; Preprocessor directive coverage (no .define).
; Preprocessor symbols are provided via -D/--define.

.ifdef VAL
        .byte 0
.else
        .byte 1
.endif

.ifndef UNKNOWN
        .byte 2
.else
        .byte 0
.endif

.include "preproc_syntax.inc"
