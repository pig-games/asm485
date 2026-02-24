.module main

.region ram, $1200, $12ff

.section code
.pub
start
    .byte $10, $11
.priv
.endsection

.section data
    .byte $22, $33
.endsection

.pack in ram : code, data

.output "build/pack-no-dsection.bin", format=bin, contiguous=false, sections=code,data
.mapfile "build/pack-no-dsection.map", symbols=public

.endmodule
