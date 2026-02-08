; Library module that defines a private .statement for cross-module use tests.

.module statement.private.export.lib
    .pub
LIBVAL .const $42

    .priv
.statement PUSHB byte:v
    .byte .v
.endstatement
.endmodule
