; Section data across modules with include

.include "section_module_use_lib.inc"

.module example.section.app
    .use example.section.include.lib (LIBVAL)
    .region ram, $1000, $10ff
    .section data
    .byte 1, LIBVAL
    .endsection
    .place data in ram
.endmodule

.end
