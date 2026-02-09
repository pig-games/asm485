; 65816 runtime state assumptions (.assume)
; Demonstrates explicit E/M/X/DBR/PBR/DP assumptions.

        .cpu 65816
        .org $123400

start:
        .assume e=native, m=16, x=16, dbr=$12, pbr=$34, dp=$2000

        lda #$1234          ; A9 34 12 (A is 16-bit)
        ldx #$5678          ; A2 78 56 (X is 16-bit)
        lda $123456         ; AD 56 34 (DBR bank match uses absolute form)
        lda $20F0           ; A5 F0 (DP assumption maps absolute address to direct-page offset)
        jmp $343210         ; 4C 10 32 (PBR bank match uses absolute JMP operand)

        sep #$20            ; A back to 8-bit
        lda #$9A            ; A9 9A

        .assume e=emulation ; forces A/X to 8-bit
        ldx #$BC            ; A2 BC

        rts

        .end
