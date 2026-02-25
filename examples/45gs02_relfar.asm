; 45GS02 relfar branch selection
; Verifies automatic short-vs-far branch resolution

        .cpu 45gs02
        .org $0800

start
        bpl far_target      ; out of short range -> relfar opcode
        bra short_target    ; in range -> regular relative opcode
        nop
short_target
        nop

        .org $0905

far_target
        rts

        .end
