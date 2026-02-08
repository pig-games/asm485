; Test: importing a private .statement across modules should fail.

.module statement.private.app
    .cpu 8085
    .use statement.private.export.lib (LIBVAL, PUSHB)
    .org $0000
    mvi a, LIBVAL
    PUSHB $AA
    hlt
.endmodule

.end
