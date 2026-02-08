; 65816 wide .const/.var listing coverage
; Ensures directive-form constants/variables keep values above 16-bit in listing output.

.module main
.cpu 65816

const_wide .const $123456
var_wide   .var   $010000
var_wide   .var   var_wide + $2345

.endmodule
