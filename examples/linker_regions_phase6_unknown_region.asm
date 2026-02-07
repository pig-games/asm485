.module main

.region ram, $1000, $10ff

.section code
    .byte $ea
.endsection

.place code in nowhere

.endmodule
