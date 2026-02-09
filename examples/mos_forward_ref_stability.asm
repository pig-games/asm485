; MOS 6502-family forward-reference sizing stability
; Verifies pass-1/pass-2 sizing stays stable across $00FF boundaries.

        .cpu 6502
        .org $00FD

m6502_start:
        lda m6502_target   ; must encode absolute: AD 01 01
        nop
m6502_target:
        rts

        .cpu 65c02
        .org $01FD

m65c02_start:
        stz m65c02_target  ; must encode absolute: 9C 01 02
        nop
m65c02_target:
        rts

        .end
