; Simple Z80 CPU test
        .cpu z80

; Basic data movement
        ld a, 0         ; load immediate
        ld b, 55h
        ld hl, 1234h    ; 16-bit load immediate
        ld a, b         ; register to register
        ld (hl), a      ; store to memory via HL (z80 syntax)
        ld m, a         ; store to memory via HL (8080 syntax)

; Arithmetic
        add a, 5        ; add immediate
        add a, b        ; add register
        sub 10h         ; subtract immediate
        inc a
        dec b

; Logic
        and 0fh         ; mask lower nibble
        or 80h
        xor a           ; clear A (same as XOR A,A)

; Logic — 2-operand forms with indexed memory
        and a, (ix+3)   ; DD A6 03
        or a, (iy+1)    ; FD B6 01
        xor a, (ix+0)   ; DD AE 00
        cp a, (iy-2)    ; FD BE FE

; Logic — 2-operand forms with half-index registers (undocumented)
        and a, ixh      ; DD A4
        or a, iyl       ; FD B5
        xor a, iyh      ; FD AC
        cp a, ixl       ; DD BD

; Jumps
        jp 1000h        ; unconditional jump
        jp nz, 2000h    ; conditional jump
        jr skip         ; relative jump
        jr nc, skip     ; conditional relative
skip:
        nop

; Z80-specific
        djnz skip       ; decrement B and jump if not zero
        ldir            ; block transfer
        cpir            ; block search

; CB-prefix bit/shift/rotate operations
        bit 3, b        ; CB 58
        set 5, (hl)     ; CB EE
        res 1, a        ; CB 8F
        rlc c           ; CB 01
        sra (hl)        ; CB 2E
        bit 2, (ix+5)   ; DD CB 05 56
        set 7, (iy-2)   ; FD CB FE FE
        srl (ix+0)      ; DD CB 00 3E
        
        .end
