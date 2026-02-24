; 45GS02 implied transfer/index opcode overrides

        .cpu 45gs02
        .org $2400

start
        dey
        txa
        txs
        tya
        tay
        tax
        tsx
        iny
        dex
        inx
        rts

        .end
