; 45GS02 stack-relative indirect indexed Y forms

        .cpu 45gs02
        .org $1100

start
        sta ($20,s),y
        lda ($21,s),y
        rts

        .end
