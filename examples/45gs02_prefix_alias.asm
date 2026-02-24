; 45GS02 prefix and alias coverage
; Uses mega65 alias and explicit/implicit prefix composition

        .cpu mega65
        .org $0900

start
        map

        ; explicit prefix bytes before regular opcode
        neg
        neg
        adc #$02

        ; explicit + implicit flat-memory prefix sequence
        nop
        lda ($22),z

        ; implicit combined prefixes from Q + flat-memory sugar
        ldq [$23],z
        stq ($24),z

        eom
        rts

        .end
