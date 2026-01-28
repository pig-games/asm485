; 65C02 Additional Addressing Modes Test
; Tests 65C02-only instructions and addressing modes

        .cpu 65c02
        .org $0300

; ========================================
; 65C02-ONLY INSTRUCTIONS
; ========================================

; STZ - Store Zero (new instruction)
        stz $20         ; 64 20 - Zero page
        stz $1234       ; 9C 34 12 - Absolute
        stz $30,x       ; 74 30 - Zero page,X
        stz $2345,x     ; 9E 45 23 - Absolute,X

; PHX/PHY/PLX/PLY - Push/Pull X and Y
        phx             ; DA
        phy             ; 5A
        plx             ; FA
        ply             ; 7A

; INC A / DEC A - Accumulator increment/decrement
        inc a           ; 1A
        dec a           ; 3A

; TRB/TSB - Test and Reset/Set Bits
        trb $40         ; 14 40 - Zero page
        trb $3456       ; 1C 56 34 - Absolute
        tsb $50         ; 04 50 - Zero page
        tsb $4567       ; 0C 67 45 - Absolute

; BRA - Branch Always
        bra skip1       ; 80 xx
        nop
        nop
skip1:

; BIT immediate (65C02 only)
        bit #$55        ; 89 55

; BIT zero page,X (65C02 only)
        bit $60,x       ; 34 60

; BIT absolute,X (65C02 only)
        bit $5678,x     ; 3C 78 56

; ========================================
; ZERO PAGE INDIRECT MODE: op ($nn)
; (65C02 only - not available on base 6502)
; ========================================
        lda ($20)       ; B2 20
        sta ($30)       ; 92 30
        adc ($40)       ; 72 40
        sbc ($50)       ; F2 50
        and ($60)       ; 32 60
        ora ($70)       ; 12 70
        eor ($80)       ; 52 80
        cmp ($90)       ; D2 90

; ========================================
; ABSOLUTE INDEXED INDIRECT: JMP ($nnnn,X)
; (65C02 only)
; ========================================
        jmp ($1234,x)   ; 7C 34 12

; ========================================
; All base 6502 modes still work
; ========================================
        lda #$42        ; A9 42 - Immediate
        lda $20         ; A5 20 - Zero page
        lda $20,x       ; B5 20 - Zero page,X
        lda $1234       ; AD 34 12 - Absolute
        lda $1234,x     ; BD 34 12 - Absolute,X
        lda $1234,y     ; B9 34 12 - Absolute,Y
        lda ($20,x)     ; A1 20 - Indexed indirect
        lda ($20),y     ; B1 20 - Indirect indexed

        rts             ; 60

        .end
