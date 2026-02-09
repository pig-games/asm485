; Simple 65816 test program
; Tests core 65816 MVP instructions currently implemented

        .cpu 65816
        .org $0400

start:
        rep #$30        ; C2 30
        sep #$20        ; E2 20
        xce             ; FB
        xba             ; EB

        pea $1234       ; F4 34 12
        pei ($20)       ; D4 20
        per near_label  ; 62 xx xx
        brl far_label   ; 82 xx xx

near_label:
        phb             ; 8B
        plb             ; AB
        phd             ; 0B
        pld             ; 2B
        phk             ; 4B
        tcd             ; 5B
        tdc             ; 7B
        tcs             ; 1B
        tsc             ; 3B

        cop #$7F        ; 02 7F
        wdm #$42        ; 42 42

        ora $10,s       ; 03 10
        ora ($11,s),y   ; 13 11

        jsl $123456     ; 22 56 34 12
        jml [$2345]     ; DC 45 23

far_label:
        rtl             ; 6B
        rts             ; 60

        .end
