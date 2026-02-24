; 65816 runtime state assumptions (.assume) + explicit operand overrides
; Demonstrates precedence: explicit override > .assume > automatic fallback.

        .cpu 65816
        .org $123400

start
        .assume e=native, m=16, x=16, dp=$2000, dbr=$12, pbr=auto

        lda #$1234          ; A9 34 12 (A is 16-bit)
        ldx #$5678          ; A2 78 56 (X is 16-bit)
        lda $123456         ; AD 56 34 (.assume dbr=$12 resolves to absolute)
        lda $123456,l       ; AF 56 34 12 (explicit long override wins)

        lda $20F0           ; A5 F0 (.assume dp=$2000 resolves to direct-page)
        lda $20F0,b         ; AD F0 20 (explicit data-bank absolute override)
        lda $20F0,d         ; A5 F0 (explicit direct-page override)

        jmp $123210         ; 4C 10 32 (PBR defaults to current .org bank $12)
        jmp $123210,k       ; 4C 10 32 (explicit program-bank absolute override)

        .assume dbr=$00
        lda $123456,l       ; AF 56 34 12 (explicit long avoids DBR mismatch)

        sep #$20            ; A back to 8-bit
        lda #$9A            ; A9 9A

        .assume e=emulation ; forces A/X to 8-bit
        ldx #$BC            ; A2 BC

        rts

        .end
