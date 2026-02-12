; In-source text encoding definitions (.encode/.cdef/.tdef/.edef).

.module main
    .org $1200

    ; Built-in encoding selection still works.
    .enc petscii
    .byte "Az", 0

    ; Define a custom encoding from scratch.
    .encode gamefont
        .cdef "A", "Z", 1
        .tdef "xy", $40
        .tdef "!?", $80, $81
        .edef "{cr}", 13
    .endencode

    .enc gamefont
    .byte "A{cr}xy!?", 0

    ; Clone an existing encoding and extend it with an escape sequence.
    .encode shifted, petscii
        .edef "{home}", 19
    .endencode

    .enc shifted
    .byte "Az{home}", 0
.endmodule
