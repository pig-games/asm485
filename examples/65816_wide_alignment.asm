; 65816 wide alignment coverage
; Ensures region/section/place align options accept values above 65535.

.module main
.cpu 65816
.region ram, $010001, $02ffff, align=$20000

.section code, align=$10000
start:
    .byte $aa
.endsection

.place code in ram, align=$8000
.endmodule
