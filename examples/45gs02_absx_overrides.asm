; 45GS02 absolute,X opcode overrides

        .cpu 45gs02
        .org $2200

start
        ora $2100,x
        and $2102,x
        eor $2104,x
        adc $2106,x
        sta $2108,x
        lda $210A,x
        cmp $210C,x
        sbc $210E,x
        rts

        .end
