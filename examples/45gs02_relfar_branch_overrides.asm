; 45GS02 relfar branch opcode overrides

        .cpu 45gs02
        .org $2800

start
        bpl far_bpl
        bmi far_bmi
        bvc far_bvc
        bvs far_bvs
        bsr far_bsr
        bra far_bra
        bcc far_bcc
        bcs far_bcs
        bne far_bne
        beq far_beq
        rts

        .org $2900

far_bpl rts
far_bmi rts
far_bvc rts
far_bvs rts
far_bsr rts
far_bra rts
far_bcc rts
far_bcs rts
far_bne rts
far_beq rts

        .end
