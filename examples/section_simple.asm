; Demonstrates sections.

.module main
    .region ram, $1000, $10ff
    .section data
    .byte 1, 2
    .endsection
    .place data in ram
.endmodule
