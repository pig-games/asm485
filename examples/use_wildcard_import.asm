; Wildcard selective import for all public symbols.

.module wildcard.import.lib
    .pub
VAL .const $11

EMITB .segment v
    .byte .v
.endsegment

PAIR .macro a, b
    .byte .a
    .byte .b
.endmacro

.statement PUSHB byte:v
    .byte .v
.endstatement
.endmodule

.module wildcard.import.app
    .cpu 8085
    .use wildcard.import.lib (*)
    .org $0000

    mvi a, VAL
    .EMITB $22
    .PAIR $33, $44
    PUSHB $55
    hlt
.endmodule

.end
