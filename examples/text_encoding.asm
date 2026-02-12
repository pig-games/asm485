; Text encoding directives and text helper directives.

.module main
    .org $1000

    ; Default encoding is ASCII.
    .byte "AZaz", 0

    ; Switch to PETSCII for text emission.
    .enc petscii
    .byte "AZaz", 0
    .text "Az"
    .null "OK"
    .ptext "dog"

    ; Switch back using the long-form alias.
    .encoding ascii
    .byte "done", 0
.endmodule
