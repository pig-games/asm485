; Library module that defines a .macro for cross-module use

.module macro.export.lib
    .pub
LIBVAL  .const $42

EMIT_PAIR .macro a, b
    .byte .a
    .byte .b
.endmacro

.endmodule
