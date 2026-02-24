; Simple 45GS02 test program
; Tests core 45GS02 instructions and sugar currently implemented

        .cpu 45gs02
        .org $0800

start
        map             ; 5C

        lda ($20),z     ; EA B1 20
        lda [$21],z     ; EA B1 21

        adcq #$01       ; 42 42 69 01
        ldq $1234       ; 42 42 AD 34 12
        stq $44         ; 42 42 85 44

        neg             ; 42
        eom             ; EA
        rts             ; 60

        .end
