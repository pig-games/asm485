; mos6502_modes.asm - Test parser refactoring for 6502 modes
    .cpu "6502"
    .org $200
    
    LDA #$10        ; Immediate
    LDA ($10,X)     ; Indexed Indirect X
    LDA ($10),Y     ; Indirect Indexed Y
