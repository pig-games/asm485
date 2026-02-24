; Demonstrates root-module metadata directives.

.module main
    .meta.name "Metadata Demo"
    .meta.version "1.0.0"
    .meta.output.name "meta-demo"
    .meta.output.z80.name "meta-demo-z80"

    .org 0000h
START
    .byte 01h, 02h, 03h, 04h
.endmodule
