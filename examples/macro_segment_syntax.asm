; Macro and segment syntax example
; Demonstrates directive-first and name-first macro forms,
; parenthesized macro calls, and segment symbol visibility.

        .cpu 8085
        .org $2000

COPY .macro src, dst
        .byte .src, .dst
.endmacro

.macro FILL(value)
        .byte .value
.endmacro

.segment INLINE(v)
VAL     .const .v
        .byte .v
.endsegment

        .COPY 1, 2
        .FILL(3)
        .INLINE 7
        .word VAL

        .end
