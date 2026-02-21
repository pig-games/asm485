; Test: cross-module segment visibility
;
; .segment definitions follow the same import rules as other symbols.
; A segment defined in a library module is only visible to the
; importing module when explicitly listed in the .use import list.
;
; Here, only LIBVAL is imported — EMIT_BYTE is NOT imported, so
; invoking it produces an error.

.module segment.cross.app
    .cpu 8085

    .use segment.export.lib (LIBVAL)

    .org $0000

    mvi a, LIBVAL       ; Works: LIBVAL is explicitly imported
    .EMIT_BYTE $AA      ; ERROR: EMIT_BYTE not imported
    hlt
.endmodule

.end
