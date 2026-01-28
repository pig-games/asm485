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
        
        .end
