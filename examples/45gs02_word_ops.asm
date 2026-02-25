; 45GS02 word direct-page operations

        .cpu 45gs02
        .org $0C00

start
        dew $20
        inw $21
        rts

        .end
