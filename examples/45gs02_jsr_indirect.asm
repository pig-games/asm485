; 45GS02 JSR indirect extensions

        .cpu 45gs02
        .org $1000

start
        jsr ($2000)
        jsr ($2002,x)
        rts

        .end
