; 45GS02 PHW extension forms

        .cpu 45gs02
        .org $0B00

start
        phw #$1234
        phw $2000
        rts

        .end
