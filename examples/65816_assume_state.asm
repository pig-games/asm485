; 65816 runtime state assumptions (.assume)
; Demonstrates explicit E/M/X/DBR/DP assumptions and inferred PBR.

        .cpu 65816
        .org $123400

start:
        .assume e=native, m=16, x=16, dp=$2000
        .assume pbr=$12, dbr=$00 ; explicit mismatch
        phk
        nop                     ; stack-neutral: does not clear pending PHK bank source
        plb                     ; PHK/PLB infers DBR from explicit PBR
        .assume pbr=$00        ; override
        .assume pbr=auto       ; restore inferred PBR from current .org bank

        lda #$1234          ; A9 34 12 (A is 16-bit)
        ldx #$5678          ; A2 78 56 (X is 16-bit)
        lda $123456         ; AD 56 34 (DBR inferred from PHK/PLB + explicit PBR)
        .assume dbr=$12     ; known explicit DBR
        pha                 ; unknown stack source for PLB inference
        plb                 ; DBR becomes unknown (no PHK/PHB pending source)
        lda $123456         ; AF 56 34 12 (unknown DBR prefers long-capable form)
        lda $20F0           ; A5 F0 (DP assumption maps absolute address to direct-page offset)
        jmp $123210         ; 4C 10 32 (PBR defaults to current .org bank $12)

        sep #$20            ; A back to 8-bit
        lda #$9A            ; A9 9A

        .assume e=emulation ; forces A/X to 8-bit
        ldx #$BC            ; A2 BC

        rts

        .end
