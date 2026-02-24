; 65C02 test program
; Tests 65C02-specific instructions

        .cpu 65c02      ; Select 65C02 CPU

        .org $2000      ; Start at $2000

; Test 65C02-only instructions
start  stz $20         ; 64 20 - Store Zero (zero page)
        stz $1234       ; 9C 34 12 - Store Zero (absolute)
        
        bra skip        ; 80 02 - Branch Always (skip 2 bytes)
        nop             ; EA
        nop             ; EA
skip   
        phx             ; DA - Push X
        phy             ; 5A - Push Y
        plx             ; FA - Pull X
        ply             ; 7A - Pull Y
        
        inc a           ; 1A - Increment Accumulator
        dec a           ; 3A - Decrement Accumulator
        
        trb $30         ; 14 30 - Test and Reset Bits (zero page)
        tsb $40         ; 04 40 - Test and Set Bits (zero page)

; Test other branch instructions
        bcc nobranch    ; 90 xx - Branch if Carry Clear
        bcs nobranch    ; B0 xx - Branch if Carry Set
        beq nobranch    ; F0 xx - Branch if Equal
        bne nobranch    ; D0 xx - Branch if Not Equal
        bmi nobranch    ; 30 xx - Branch if Minus
        bpl nobranch    ; 10 xx - Branch if Plus
        bvc nobranch    ; 50 xx - Branch if Overflow Clear
        bvs nobranch    ; 70 xx - Branch if Overflow Set

nobranch
; Test immediate mode (including 65C02-only BIT #imm)
        lda #$42        ; A9 42 - Load immediate
        ldx #$10        ; A2 10
        ldy #$20        ; A0 20
        bit #$55        ; 89 55 - BIT immediate (65C02 only)
        adc #$01        ; 69 01
        and #$0F        ; 29 0F
        ora #$F0        ; 09 F0
        eor #$AA        ; 49 AA

; Common 6502 instructions still work
        lda $50         ; A5 50
        sta $60         ; 85 60
        rts             ; 60

        .end
