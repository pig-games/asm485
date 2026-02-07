.module main

.region rom, $8000, $80ff, align=1

.section code, align=1
.pub
entry:
    .word data_start
.priv
    .byte $ea
.endsection

.section data, align=2
data_start:
    .byte 1, 2, 3
.endsection

.section zero, kind=bss, align=1
    .res byte, 4
.endsection

.pack in rom : code, data, zero

.output "build/full.prg", format=prg, contiguous=false, sections=code,data
.output "build/full-image.bin", format=bin, image="$8000..$8010", fill=$ff, contiguous=false, sections=code,data
.mapfile "build/full.map", symbols=all
.exportsections dir="build/full_sections", format=bin, include=bss

.endmodule
