; 45GS02 short relative branch opcode overrides

        .cpu 45gs02
        .org $2700

start
        bpl l1
l1      bmi l2
l2      bvc l3
l3      bvs l4
l4      bra l5
l5      bcc l6
l6      bcs l7
l7      bne l8
l8      beq done
done    rts

        .end
