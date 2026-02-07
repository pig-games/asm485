.module main

.region ram, $1000, $10ff
.region rom, $8000, $80ff

.section code, region=ram
    .byte $ea
.endsection

.place code in rom

.endmodule
