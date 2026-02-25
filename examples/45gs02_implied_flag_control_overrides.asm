; 45GS02 implied flag-control opcode overrides

        .cpu 45gs02
        .org $2500

start
        clc
        sec
        cli
        sei
        clv
        cld
        sed
        rts

        .end
