; 45GS02 extension mnemonics beyond MAP/EOM/NEG

        .cpu 45gs02
        .org $0A00

start
        cle
        see
        inz
        tys
        dez
        taz
        tab
        tza
        tba
        tsy

        ldz #$34
        ldz $1234
        ldz $1234,x

        cpz #$10
        cpz $20
        cpz $1234

        rts

        .end
