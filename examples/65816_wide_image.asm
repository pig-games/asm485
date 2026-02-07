; 65816 wide-address placement and output example
; Exercises >64KiB region placement, wide HEX records, and wide .output metadata.

        .module main
        .cpu 65816

        .region bank12, $123400, $12341f

        .section code
start:
        rep #$30
        sep #$10
        lda $123456
        sta $12345a,x
        jsl $123456
        wdm #$42
        rtl
        .endsection

        .place code in bank12

        .output "build/65816-wide-image.bin", format=bin, image="$123400..$12341f", fill=$ff, contiguous=false, loadaddr=$123456, sections=code

        .endmodule

        .end
