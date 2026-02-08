; Test: successful cross-module statement import
;
; When PUSHB is explicitly listed in the .use import list,
; the statement defined in the library module becomes available.

.module statement.cross.ok.app
    .cpu 8085

    .use statement.export.lib (LIBVAL, PUSHB)

    .org $0000

    mvi a, LIBVAL       ; Use the exported const ($42)
    PUSHB $AA           ; Invoke the exported statement
    PUSHB $BB
    hlt
.endmodule

.end
