; 45GS02 stack transfer operations for Z register

        .cpu 45gs02
        .org $0E00

start
        phz
        plz
        rts

        .end
