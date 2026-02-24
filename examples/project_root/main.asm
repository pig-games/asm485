; Root-folder example with a single root module.

.module main
    .use util
    .org 0000h
START
    .byte 01h, 02h
    .word util.VALUE
.endmodule
