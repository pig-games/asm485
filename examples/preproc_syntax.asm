; Preprocessor directive and macro coverage
; This file is preprocessed first, so we can safely use .define/.ifdef/.include.

.define VAL 7
.define ADD(a,b) (a + b)
.define TWICE(x) (x + x)

.ifdef VAL
        .byte ADD(1,2)
.else
        .byte 0
.endif

.ifndef UNKNOWN
        .byte TWICE(3)
.else
        .byte 0
.endif

.include "preproc_syntax.inc"
