.module main

.region ram, $1000, $10ff

.section code
.pub
start
    .byte $42, $43
.priv
.endsection

.place code in ram

.output "build/no-dsection.bin", format=bin, sections=code
.mapfile "build/no-dsection.map", symbols=public

.endmodule
