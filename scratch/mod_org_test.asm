.module main
    .cpu 6502
    .org $0801
start:
    lda #0
    beq ok
    nop
ok:
    rts
    .output "build/mod-org-test.prg", format=prg
.endmodule
