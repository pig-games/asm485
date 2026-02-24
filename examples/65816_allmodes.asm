; 65816 MVP Addressing/Instruction Coverage
; Covers currently implemented 65816-specific forms in this branch.

        .cpu 65816
        .org $0800

; ========================================
; CONTROL FLOW / LONG CONTROL
; ========================================
        brl long_target     ; 82 xx xx
        nop                 ; EA
long_target
        jml $C0FFEE         ; 5C EE FF C0
        jsl $00ABCD         ; 22 CD AB 00
        jmp [$3456]         ; DC 56 34
        jml [$3456]         ; DC 56 34 (alias)
        rtl                 ; 6B

; ========================================
; MODE/CONTROL
; ========================================
        rep #$30            ; C2 30
        sep #$10            ; E2 10
        xce                 ; FB
        xba                 ; EB

; ========================================
; WIDTH-SENSITIVE IMMEDIATES
; ========================================
        rep #$30            ; C2 30 (A/X -> 16-bit immediates)
        lda #$1234          ; A9 34 12
        ldx #$5678          ; A2 78 56
        sep #$20            ; E2 20 (A -> 8-bit immediate)
        lda #$12            ; A9 12
        sep #$10            ; E2 10 (X/Y -> 8-bit immediate)
        ldx #$34            ; A2 34

; ========================================
; STACK/REGISTER CONTROL
; ========================================
        phb                 ; 8B
        plb                 ; AB
        phd                 ; 0B
        pld                 ; 2B
        phk                 ; 4B
        tcd                 ; 5B
        tdc                 ; 7B
        tcs                 ; 1B
        tsc                 ; 3B

; ========================================
; MEMORY / IMMEDIATE CONTROL
; ========================================
        pea $4567           ; F4 67 45
        pei ($44)           ; D4 44
        per rel_target      ; 62 xx xx
        cop #$99            ; 02 99
        wdm #$55            ; 42 55

; ========================================
; BLOCK MOVE
; ========================================
        mvn $01,$02         ; 54 01 02
        mvp $03,$04         ; 44 03 04

; ========================================
; 65816 STACK-RELATIVE ADDRESSING
; ========================================
        ora $20,s           ; 03 20
        ora ($21,s),y       ; 13 21
        lda $22,s           ; A3 22
        lda ($23,s),y       ; B3 23
        sta $24,s           ; 83 24
        sta ($25,s),y       ; 93 25
        and ($26,s),y       ; 33 26
        eor $27,s           ; 43 27
        cmp ($28,s),y       ; D3 28

; ========================================
; 65816 LONG MEMORY FORMS
; ========================================
        lda $123456         ; AF 56 34 12
        lda $123456,x       ; BF 56 34 12
        sta $12345A         ; 8F 5A 34 12
        sta $12345A,x       ; 9F 5A 34 12

; ========================================
; 65816 BRACKETED LONG-INDIRECT FORMS
; ========================================
        lda [$30]           ; A7 30
        lda [$30],y         ; B7 30
        sta [$31]           ; 87 31
        sta [$31],y         ; 97 31

; Shared family instructions still valid on 65816
        lda #$12
        sta $2000

rel_target
        rts

        .end
