; 65816 wide mapfile coverage
; Ensures map output preserves wide symbol values and high 24-bit addresses.

.module main
.cpu 65816

.region hi, $FF0000, $FF00FF
wide_const .const $89ABCDEF

.section code
entry
    .byte $ea
.endsection

.place code in hi
.mapfile "build/65816-wide-mapfile.map", symbols=all

.endmodule
