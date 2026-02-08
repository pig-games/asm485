; Test: cross-module statement visibility (expected error)
;
; .statement definitions follow the same import rules as other symbols.
; A statement defined in a library module is only visible to the
; importing module when explicitly listed in the .use import list.
;
; Here, only LIBVAL is imported — PUSHB is NOT imported, so
; invoking it produces an error.

.module statement.cross.app
    .cpu 8085

    .use statement.export.lib (LIBVAL)

    .org $0000

    mvi a, LIBVAL       ; Works: LIBVAL is explicitly imported
    PUSHB $AA           ; ERROR: PUSHB not imported
    hlt
.endmodule

.end
