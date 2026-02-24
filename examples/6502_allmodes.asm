; 6502 All Addressing Modes Test
; Tests every addressing mode supported by the base 6502

        .cpu 6502
        .org $0200

; ========================================
; ACCUMULATOR MODE: op A
; ========================================
        asl a           ; 0A
        lsr a           ; 4A
        rol a           ; 2A
        ror a           ; 6A

; ========================================
; IMMEDIATE MODE: op #$nn
; ========================================
        lda #$42        ; A9 42
        ldx #$10        ; A2 10
        ldy #$20        ; A0 20
        adc #$05        ; 69 05
        sbc #$03        ; E9 03
        and #$0F        ; 29 0F
        ora #$F0        ; 09 F0
        eor #$AA        ; 49 AA
        cmp #$80        ; C9 80
        cpx #$40        ; E0 40
        cpy #$60        ; C0 60

; ========================================
; ZERO PAGE MODE: op $nn
; ========================================
        lda $20         ; A5 20
        ldx $30         ; A6 30
        ldy $40         ; A4 40
        sta $50         ; 85 50
        stx $60         ; 86 60
        sty $70         ; 84 70
        adc $80         ; 65 80
        sbc $90         ; E5 90
        and $A0         ; 25 A0
        ora $B0         ; 05 B0
        eor $C0         ; 45 C0
        cmp $D0         ; C5 D0
        cpx $E0         ; E4 E0
        cpy $F0         ; C4 F0
        asl $10         ; 06 10
        lsr $11         ; 46 11
        rol $12         ; 26 12
        ror $13         ; 66 13
        inc $14         ; E6 14
        dec $15         ; C6 15
        bit $16         ; 24 16

; ========================================
; ZERO PAGE,X MODE: op $nn,X
; ========================================
        lda $20,x       ; B5 20
        sta $30,x       ; 95 30
        ldy $40,x       ; B4 40
        sty $50,x       ; 94 50
        adc $60,x       ; 75 60
        sbc $70,x       ; F5 70
        and $80,x       ; 35 80
        ora $90,x       ; 15 90
        eor $A0,x       ; 55 A0
        cmp $B0,x       ; D5 B0
        asl $C0,x       ; 16 C0
        lsr $D0,x       ; 56 D0
        rol $E0,x       ; 36 E0
        ror $F0,x       ; 76 F0
        inc $10,x       ; F6 10
        dec $11,x       ; D6 11

; ========================================
; ZERO PAGE,Y MODE: op $nn,Y
; ========================================
        ldx $20,y       ; B6 20
        stx $30,y       ; 96 30

; ========================================
; ABSOLUTE MODE: op $nnnn
; ========================================
        lda $1234       ; AD 34 12
        ldx $2345       ; AE 45 23
        ldy $3456       ; AC 56 34
        sta $4567       ; 8D 67 45
        stx $5678       ; 8E 78 56
        sty $6789       ; 8C 89 67
        adc $789A       ; 6D 9A 78
        sbc $89AB       ; ED AB 89
        and $9ABC       ; 2D BC 9A
        ora $ABCD       ; 0D CD AB
        eor $BCDE       ; 4D DE BC
        cmp $CDEF       ; CD EF CD
        cpx $DEF0       ; EC F0 DE
        cpy $EF01       ; CC 01 EF
        asl $1000       ; 0E 00 10
        lsr $1001       ; 4E 01 10
        rol $1002       ; 2E 02 10
        ror $1003       ; 6E 03 10
        inc $1004       ; EE 04 10
        dec $1005       ; CE 05 10
        bit $1006       ; 2C 06 10
        jmp $1007       ; 4C 07 10
        jsr $1008       ; 20 08 10

; ========================================
; ABSOLUTE,X MODE: op $nnnn,X
; ========================================
        lda $1234,x     ; BD 34 12
        sta $2345,x     ; 9D 45 23
        ldy $3456,x     ; BC 56 34
        adc $4567,x     ; 7D 67 45
        sbc $5678,x     ; FD 78 56
        and $6789,x     ; 3D 89 67
        ora $789A,x     ; 1D 9A 78
        eor $89AB,x     ; 5D AB 89
        cmp $9ABC,x     ; DD BC 9A
        asl $ABCD,x     ; 1E CD AB
        lsr $BCDE,x     ; 5E DE BC
        rol $CDEF,x     ; 3E EF CD
        ror $DEF0,x     ; 7E F0 DE
        inc $EF01,x     ; FE 01 EF
        dec $F012,x     ; DE 12 F0

; ========================================
; ABSOLUTE,Y MODE: op $nnnn,Y
; ========================================
        lda $1234,y     ; B9 34 12
        sta $2345,y     ; 99 45 23
        ldx $3456,y     ; BE 56 34
        adc $4567,y     ; 79 67 45
        sbc $5678,y     ; F9 78 56
        and $6789,y     ; 39 89 67
        ora $789A,y     ; 19 9A 78
        eor $89AB,y     ; 59 AB 89
        cmp $9ABC,y     ; D9 BC 9A

; ========================================
; INDIRECT MODE: JMP ($nnnn)
; ========================================
        jmp ($1234)     ; 6C 34 12

; ========================================
; INDEXED INDIRECT MODE: op ($nn,X)
; ========================================
        lda ($20,x)     ; A1 20
        sta ($30,x)     ; 81 30
        adc ($40,x)     ; 61 40
        sbc ($50,x)     ; E1 50
        and ($60,x)     ; 21 60
        ora ($70,x)     ; 01 70
        eor ($80,x)     ; 41 80
        cmp ($90,x)     ; C1 90

; ========================================
; INDIRECT INDEXED MODE: op ($nn),Y
; ========================================
        lda ($20),y     ; B1 20
        sta ($30),y     ; 91 30
        adc ($40),y     ; 71 40
        sbc ($50),y     ; F1 50
        and ($60),y     ; 31 60
        ora ($70),y     ; 11 70
        eor ($80),y     ; 51 80
        cmp ($90),y     ; D1 90

; ========================================
; RELATIVE MODE: Branches
; ========================================
branch_test
        bcc branch_test ; 90 FE (branch to self)
        bcs $+2         ; B0 00
        beq $+4         ; F0 02
        bne forward     ; D0 xx
        bmi $+2         ; 30 00
        bpl $+2         ; 10 00
        bvc $+2         ; 50 00
        bvs $+2         ; 70 00
forward

; ========================================
; IMPLIED MODE: No operand
; ========================================
        nop             ; EA
        clc             ; 18
        sec             ; 38
        cli             ; 58
        sei             ; 78
        clv             ; B8
        cld             ; D8
        sed             ; F8
        tax             ; AA
        txa             ; 8A
        tay             ; A8
        tya             ; 98
        tsx             ; BA
        txs             ; 9A
        pha             ; 48
        pla             ; 68
        php             ; 08
        plp             ; 28
        inx             ; E8
        dex             ; CA
        iny             ; C8
        dey             ; 88
        brk             ; 00
        rti             ; 40
        rts             ; 60

        .end
