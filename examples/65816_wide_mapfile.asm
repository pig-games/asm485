; 65816 wide mapfile coverage
; Ensures map output preserves full 32-bit addresses and symbol values.

.module main
.cpu 65816

.region hi, $FF000000, $FF0000FF
wide_const .const $89ABCDEF

.section code
entry:
    .byte $ea
.endsection

.place code in hi
.mapfile "build/65816-wide-mapfile.map", symbols=all

.endmodule
