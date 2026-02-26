.cpu z80
Loop ld a,(ix+1)
    adc a,b
.cpu m6502
main lda #$10,x
    sta ($20),y
