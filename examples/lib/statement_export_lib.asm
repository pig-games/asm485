; Library module that defines a .statement for cross-module use

.module statement.export.lib
    .pub
LIBVAL  .const $42

.statement PUSHB byte:v
    .byte .v
.endstatement

.endmodule
