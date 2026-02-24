.module main

.region ram, $1000, $10ff

.section code
.pub
start
    .byte $42, $43
.priv
.endsection

.place code in ram

.output "build/minimal.bin", format=bin, sections=code
.mapfile "build/minimal.map", symbols=public
.exportsections dir="build/minimal_sections", format=bin

.endmodule
