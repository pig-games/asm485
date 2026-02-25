; 45GS02 implied stack/control opcode overrides

        .cpu 45gs02
        .org $2600

start
        php
        pha
        phy
        plp
        pla
        ply
        phx
        plx
        rti

        .end
