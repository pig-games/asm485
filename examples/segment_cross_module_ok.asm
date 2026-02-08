; Test: successful cross-module segment import
;
; When EMIT_BYTE is explicitly listed in the .use import list,
; the segment defined in the library module becomes available.

.module segment.cross.ok.app
    .cpu 8085

    .use segment.export.lib (LIBVAL, EMIT_BYTE)

    .org $0000

    mvi a, LIBVAL       ; Use the exported const ($42)
    .EMIT_BYTE $AA      ; Invoke the exported segment
    .EMIT_BYTE $BB
    hlt
.endmodule

.end
