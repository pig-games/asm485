.module main
    .cpu 6502
    .region ram, $0801, $08ff
    .section code
start:
    lda #0
    beq ok
    nop
ok:
    rts
.endsection
    .place code in ram
    .output "build/mod-section-test.prg", format=prg, sections=code
.endmodule
