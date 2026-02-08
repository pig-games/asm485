; Library module that defines a .segment for cross-module use

.module segment.export.lib
    .pub
LIBVAL  .const $42

EMIT_BYTE .segment v
    .byte .v
.endsegment

.endmodule
