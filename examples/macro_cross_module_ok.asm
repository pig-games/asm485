; Test: successful cross-module macro import
;
; When EMIT_PAIR is explicitly listed in the .use import list,
; the macro defined in the library module becomes available.

.module macro.cross.ok.app
    .cpu 8085

    .use macro.export.lib (LIBVAL, EMIT_PAIR)

    .org $0000

    mvi a, LIBVAL       ; Use the exported const ($42)
    .EMIT_PAIR $AA, $BB ; Invoke the exported macro
    .EMIT_PAIR $CC, $DD
    hlt
.endmodule

.end
