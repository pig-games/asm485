; Macro syntax examples

        .org 2000h

COPY .macro src, dst
        lda .src
        sta .dst
.endmacro

PAIR .macro a, b=2
        .byte .a, .b
.endmacro

TEXT .macro msg
        .byte @1
        .word .@
.endmacro

LOCAL .macro
local   .const 9
.endmacro

INLINE .segment val
        .byte .val
.endsegment

        .COPY $12, $34
        .PAIR 1
        .TEXT 1+2
        .INLINE 7

foo     .LOCAL
        .word foo.local
        .end
