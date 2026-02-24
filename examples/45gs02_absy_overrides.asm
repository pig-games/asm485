; 45GS02 absolute,Y opcode overrides

        .cpu 45gs02
        .org $2100

start
        ora $2000,y
        and $2002,y
        eor $2004,y
        adc $2006,y
        sta $2008,y
        lda $200A,y
        cmp $200C,y
        sbc $200E,y
        rts

        .end
