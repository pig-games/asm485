.cpu z80
Loop    ld A, (IX+1)
        adc A, B
.cpu m6502
main    lda #$10, X
        sta ($20), Y
