; 45GS02 immediate ORA/SBC opcode variants

        .cpu 45gs02
        .org $1300

start
        ora #$12
        sbc #$34
        rts

        .end
