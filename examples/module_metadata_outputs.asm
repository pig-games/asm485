; Demonstrates metadata output selection directives.

.module main
    .meta
        .output
            .list
            .hex "meta-hex"
            .bin "0000:0003"
        .endoutput
    .endmeta

    .org 0000h
START
    .byte 01h, 02h, 03h, 04h
.endmodule
