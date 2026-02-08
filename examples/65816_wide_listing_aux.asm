; 65816 wide listing auxiliary-value coverage
; Ensures .equ and reserve-size listing columns keep values above 16-bit.

.module main
.cpu 65816

wide_value = $123456

.section scratch, kind=bss
buffer:
    .res byte, $123456
.endsection

.endmodule
