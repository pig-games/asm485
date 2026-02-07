.module main

.region ram, $1000, $10ff

.section a, align=1
    .byte $aa
.endsection

.section b, align=2
    .byte $bb
.endsection

.place a in ram
.place b in ram

.output "build/phase6-gap.bin", format=bin, sections=a,b

.endmodule
