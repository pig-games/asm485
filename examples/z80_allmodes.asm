; Z80 All Instruction Modes Test
; Comprehensive test of Z80-specific instructions and addressing modes
; including undocumented half-index registers and 2-operand logic forms.

        .cpu z80
        .org 0000h

; ========================================
; LD — INDEX REGISTER LOADS
; ========================================
        ld ix, 1234h    ; DD 21 34 12
        ld iy, 5678h    ; FD 21 78 56
        ld sp, ix       ; DD F9
        ld sp, iy       ; FD F9

; ========================================
; LD — INDEXED MEMORY (IX+d / IY+d)
; ========================================
        ld a, (ix+5)    ; DD 7E 05
        ld b, (iy-3)    ; FD 46 FD
        ld (ix+10), c   ; DD 71 0A
        ld (iy+0), d    ; FD 72 00
        ld (ix+1), 42h  ; DD 36 01 42

; ========================================
; LD — INDIRECT 16-BIT LOADS
; ========================================
        ld bc, (4000h)  ; ED 4B 00 40
        ld de, (4002h)  ; ED 5B 02 40
        ld ix, (4006h)  ; DD 2A 06 40
        ld iy, (4008h)  ; FD 2A 08 40
        ld (5000h), bc  ; ED 43 00 50
        ld (5002h), de  ; ED 53 02 50
        ld (5006h), ix  ; DD 22 06 50
        ld (5008h), iy  ; FD 22 08 50

; ========================================
; LD — SPECIAL REGISTERS
; ========================================
        ld a, i         ; ED 57
        ld a, r         ; ED 5F
        ld i, a         ; ED 47
        ld r, a         ; ED 4F

; ========================================
; PUSH / POP INDEX REGISTERS
; ========================================
        push ix         ; DD E5
        push iy         ; FD E5
        pop ix          ; DD E1
        pop iy          ; FD E1

; ========================================
; EXCHANGE INSTRUCTIONS
; ========================================
        ex af, af'      ; 08
        exx             ; D9
        ex (sp), ix     ; DD E3
        ex (sp), iy     ; FD E3

; ========================================
; INDEX REGISTER ARITHMETIC (16-BIT)
; ========================================
        add ix, bc      ; DD 09
        add ix, de      ; DD 19
        add ix, ix      ; DD 29
        add ix, sp      ; DD 39
        add iy, bc      ; FD 09
        add iy, de      ; FD 19
        add iy, iy      ; FD 29
        add iy, sp      ; FD 39
        inc ix          ; DD 23
        dec ix          ; DD 2B
        inc iy          ; FD 23
        dec iy          ; FD 2B

; ========================================
; 16-BIT ARITHMETIC WITH CARRY (ED PREFIX)
; ========================================
        adc hl, bc      ; ED 4A
        adc hl, de      ; ED 5A
        adc hl, hl      ; ED 6A
        adc hl, sp      ; ED 7A
        sbc hl, bc      ; ED 42
        sbc hl, de      ; ED 52
        sbc hl, hl      ; ED 62
        sbc hl, sp      ; ED 72

; ========================================
; INDEXED MEMORY INC / DEC
; ========================================
        inc (ix+3)      ; DD 34 03
        dec (ix+3)      ; DD 35 03
        inc (iy-1)      ; FD 34 FF
        dec (iy-1)      ; FD 35 FF

; ========================================
; INDEXED MEMORY ARITHMETIC — 1-OPERAND FORMS
; ========================================
        add a, (ix+2)   ; DD 86 02
        adc a, (ix+2)   ; DD 8E 02
        sub (ix+2)      ; DD 96 02
        sbc a, (ix+2)   ; DD 9E 02
        and (ix+2)      ; DD A6 02
        xor (ix+2)      ; DD AE 02
        or (ix+2)       ; DD B6 02
        cp (ix+2)       ; DD BE 02

; ========================================
; INDEXED MEMORY LOGIC — 2-OPERAND FORMS
; These are the explicit A,<src> forms:
; ========================================
        and a, (ix+4)   ; DD A6 04
        or a, (ix+4)    ; DD B6 04
        xor a, (ix+4)   ; DD AE 04
        cp a, (ix+4)    ; DD BE 04
        and a, (iy+4)   ; FD A6 04
        or a, (iy+4)    ; FD B6 04
        xor a, (iy+4)   ; FD AE 04
        cp a, (iy+4)    ; FD BE 04
        sub a, (ix+4)   ; DD 96 04
        sub a, (iy+4)   ; FD 96 04

; ========================================
; HALF-INDEX REGISTERS (UNDOCUMENTED)
; IXH, IXL, IYH, IYL
; ========================================

; --- Loads ---
        ld a, ixh       ; DD 7C
        ld a, ixl       ; DD 7D
        ld b, ixh       ; DD 44
        ld c, ixl       ; DD 4D
        ld ixh, 10h     ; DD 26 10
        ld ixl, 20h     ; DD 2E 20
        ld iyh, 30h     ; FD 26 30
        ld iyl, 40h     ; FD 2E 40

; --- Inc / Dec ---
        inc ixh         ; DD 24
        dec ixh         ; DD 25
        inc ixl         ; DD 2C
        dec ixl         ; DD 2D
        inc iyh         ; FD 24
        dec iyh         ; FD 25
        inc iyl         ; FD 2C
        dec iyl         ; FD 2D

; --- Arithmetic — 1-operand forms ---
        add a, ixh      ; DD 84
        adc a, ixl      ; DD 8D
        sub ixh         ; DD 94
        sbc a, ixl      ; DD 9D
        and ixh         ; DD A4
        xor ixl         ; DD AD
        or iyh          ; FD B4
        cp iyl          ; FD BD

; --- Arithmetic — 2-operand forms (A,<half>) ---
;     Explicit A,<src> forms for logic operations:
        and a, ixh      ; DD A4
        and a, ixl      ; DD A5
        or a, ixh       ; DD B4
        or a, ixl       ; DD B5
        xor a, ixh      ; DD AC
        xor a, ixl      ; DD AD
        cp a, ixh       ; DD BC
        cp a, ixl       ; DD BD
        and a, iyh      ; FD A4
        and a, iyl      ; FD A5
        or a, iyh       ; FD B4
        or a, iyl       ; FD B5
        xor a, iyh      ; FD AC
        xor a, iyl      ; FD AD
        cp a, iyh       ; FD BC
        cp a, iyl       ; FD BD
        sub a, ixh      ; DD 94
        sub a, ixl      ; DD 95

; ========================================
; CB-PREFIX — ROTATE / SHIFT (REGISTERS)
; ========================================
        rlc b           ; CB 00
        rrc c           ; CB 09
        rl d            ; CB 12
        rr e            ; CB 1B
        sla h           ; CB 24
        sra l           ; CB 2D
        sll a           ; CB 37  (undocumented)
        srl b           ; CB 38

; ========================================
; CB-PREFIX — ROTATE / SHIFT ON (HL)
; ========================================
        rlc (hl)        ; CB 06
        rrc (hl)        ; CB 0E
        rl (hl)         ; CB 16
        rr (hl)         ; CB 1E
        sla (hl)        ; CB 26
        sra (hl)        ; CB 2E
        sll (hl)        ; CB 36  (undocumented)
        srl (hl)        ; CB 3E

; ========================================
; CB-PREFIX — BIT / SET / RES
; ========================================
        bit 0, a        ; CB 47
        bit 3, b        ; CB 58
        bit 7, (hl)     ; CB 7E
        set 0, c        ; CB C1
        set 5, (hl)     ; CB EE
        res 1, a        ; CB 8F
        res 6, d        ; CB B2

; ========================================
; CB-PREFIX — INDEXED ROTATE / SHIFT
; ========================================
        rlc (ix+5)      ; DD CB 05 06
        rrc (iy-2)      ; FD CB FE 0E
        rl (ix+1)       ; DD CB 01 16
        rr (iy+3)       ; FD CB 03 1E
        sla (ix+0)      ; DD CB 00 26
        sra (iy+7)      ; FD CB 07 2E
        sll (ix+2)      ; DD CB 02 36  (undocumented)
        srl (iy-1)      ; FD CB FF 3E

; ========================================
; CB-PREFIX — INDEXED BIT / SET / RES
; ========================================
        bit 2, (ix+5)   ; DD CB 05 56
        bit 4, (iy-3)   ; FD CB FD 66
        set 7, (ix+0)   ; DD CB 00 FE
        set 1, (iy+6)   ; FD CB 06 CE
        res 3, (ix-1)   ; DD CB FF 9E
        res 0, (iy+2)   ; FD CB 02 86

; ========================================
; RELATIVE JUMPS
; ========================================
loop:   jr loop         ; 18 FE  (self-loop)
        jr z, loop      ; 28 FC  (backward)
        jr nz, $        ; 20 FE  (self-loop via $)
        jr c, $         ; 38 FE
        jr nc, $        ; 30 FE
        djnz loop       ; 10 F4  (backward)

; ========================================
; JP / CALL VIA INDEX REGISTER
; ========================================
        jp (ix)         ; DD E9
        jp (iy)         ; FD E9

; ========================================
; IM — INTERRUPT MODES
; ========================================
        im 0            ; ED 46
        im 1            ; ED 56
        im 2            ; ED 5E

; ========================================
; RETURN VARIANTS
; ========================================
        reti            ; ED 4D
        retn            ; ED 45

; ========================================
; BLOCK TRANSFER
; ========================================
        ldi             ; ED A0
        ldir            ; ED B0
        ldd             ; ED A8
        lddr            ; ED B8

; ========================================
; BLOCK COMPARE
; ========================================
        cpir            ; ED B1
        cpd             ; ED A9
        cpdr            ; ED B9

; ========================================
; BLOCK I/O
; ========================================
        ini             ; ED A2
        inir            ; ED B2
        ind             ; ED AA
        indr            ; ED BA
        outi            ; ED A3
        otir            ; ED B3
        outd            ; ED AB
        otdr            ; ED BB

; ========================================
; EXTENDED I/O
; ========================================
        in a, (0C0h)    ; DB C0   (basic I/O)
        out (080h), a   ; D3 80   (basic I/O)
        in b, (c)       ; ED 40
        in c, (c)       ; ED 48
        in d, (c)       ; ED 50
        in e, (c)       ; ED 58
        in h, (c)       ; ED 60
        in l, (c)       ; ED 68
        in a, (c)       ; ED 78
        out (c), b      ; ED 41
        out (c), c      ; ED 49
        out (c), d      ; ED 51
        out (c), e      ; ED 59
        out (c), h      ; ED 61
        out (c), l      ; ED 69
        out (c), a      ; ED 79

; ========================================
; MISC ED-PREFIX
; ========================================
        neg             ; ED 44
        rld             ; ED 6F
        rrd             ; ED 67

        .end
