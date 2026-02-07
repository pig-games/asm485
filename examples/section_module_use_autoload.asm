; Section data across modules with autoload

.module example.section.app
    .use example.section.lib (LIBVAL)
    .region ram, $1000, $10ff
    .section data
    .byte 1, LIBVAL
    .endsection
    .place data in ram
.endmodule

.end
