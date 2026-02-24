; 65816 wide-address BSS reserve coverage
; Ensures .res can reserve beyond 64 KiB when placed in a wide region.

.module main
.cpu 65816
.region ram, $010000, $04ffff

.section vars, kind=bss
start
    .res long, 20000
end_label
.endsection

.place vars in ram
.endmodule
