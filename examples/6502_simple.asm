; Simple 6502 test program
; Tests basic instruction encoding

        .cpu 6502       ; Select 6502 CPU

        .org $1000      ; Start at $1000

; Test implied instructions
start  nop             ; EA
        clc             ; 18
        sec             ; 38
        cli             ; 58
        sei             ; 78
        
; Test accumulator mode
        asl a           ; 0A
        lsr a           ; 4A
        rol a           ; 2A
        ror a           ; 6A

; Test immediate mode
        lda #$42        ; A9 42
        ldx #$10        ; A2 10
        ldy #255        ; A0 FF
        adc #$01        ; 69 01
        sbc #$02        ; E9 02
        cmp #$00        ; C9 00
        cpx #$80        ; E0 80
        cpy #$7F        ; C0 7F
        and #$0F        ; 29 0F
        ora #$F0        ; 09 F0
        eor #$AA        ; 49 AA

; Test zero page
        lda $42         ; A5 42
        sta $50         ; 85 50
        ldx $60         ; A6 60
        ldy $70         ; A4 70

; Test absolute
        lda $1234       ; AD 34 12
        sta $5678       ; 8D 78 56
        jmp $2000       ; 4C 00 20

; Test implied again
        rts             ; 60

        .end
