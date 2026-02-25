; 45GS02 STY/STX absolute-family opcode overrides

        .cpu 45gs02
        .org $2300

start
        sty $3000,x
        sty $3002
        stx $3004
        stx $3006,y
        rts

        .end
