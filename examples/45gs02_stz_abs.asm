; 45GS02 STZ absolute forms

        .cpu 45gs02
        .org $1200

start
        stz $2000
        stz $2002,x
        rts

        .end
