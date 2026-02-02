; Module basics

.module alpha
    .org 1000h
VALUE .const 1
    .byte VALUE
.endmodule

.module beta
    .org 2000h
VALUE .const 2
    .byte VALUE
.endmodule

.end
