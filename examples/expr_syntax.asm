; Expression syntax coverage for 64tass-style operators and literals
; Tests expressions and labels in all addressing modes for 8080/8085 and 6502/65C02

; ============================================================================
; PART 1: 8080/8085 FAMILY - Expressions in addressing modes
; ============================================================================
        .cpu 8085
        .org 0000h

; --- Constants and labels for expression testing ---
BASE            .const  $10
OFFSET          .const  $05
MASK            .const  $0F
PAGE            .const  $1200
TABLE           .const  $2000

; Numeric literal formats
num_dec         .const  123
num_hex         .const  0a6h
num_hex_pref    .const  $1f
num_bin         .const  1010b
num_bin_pref    .const  %1010       ; % prefix for binary
num_bin_long    .const  %11110000   ; longer binary value
num_oct         .const  17o
num_oct_q       .const  17q

; Digit separators with underscore
num_sep_dec     .const  1_000_000   ; decimal with separators
num_sep_hex     .const  $FF_00      ; hex with separators
num_sep_bin     .const  %1111_0000  ; binary with separators
num_sep_suf     .const  1111_0000b  ; suffix binary with separators

; Unary operators
hi_byte         .const  >$1234
lo_byte         .const  <$1234
not_zero        .const  !0
not_one         .const  !1
bit_not         .const  ~$00ff
neg_one         .const  -1

; Arithmetic and shifts
pow1            .const  2 ** 3
pow2            .const  3 ** 2 ** 2
shift_l         .const  1 << 4
shift_r         .const  $ff >> 4

; Comparisons
cmp_eq          .const  (3 == 3)
cmp_ne          .const  (3 != 4)
cmp_ne_alt      .const  (3 <> 4)
cmp_le          .const  (3 <= 4)
cmp_lt          .const  (3 < 4)
cmp_ge          .const  (4 >= 3)
cmp_gt          .const  (4 > 3)

; Bitwise and logical
bit_and         .const  ($f0 & $0f)
bit_or          .const  ($f0 | $0f)
bit_xor         .const  ($f0 ^ $0f)
log_and         .const  (2 && 3)
log_or          .const  (0 || 3)
log_xor         .const  (2 ^^ 3)

; Ternary
ternary1        .const  0 ? 1 : 2
ternary2        .const  5 ? 7 : 9
ternary3        .const  (0 || 1) ? (2 + 3) : (4 + 5)

; String constants
char_a          .const  'A'
char_ab         .const  'AB'

; ============================================================================
; 8085 IMMEDIATE MODE: MVI reg, imm8  /  LXI rp, imm16
; ============================================================================
i8085_imm
        mvi a, BASE             ; label
        mvi a, BASE + OFFSET    ; expression with labels
        mvi a, >PAGE            ; high byte operator
        mvi a, <PAGE            ; low byte operator
        mvi a, MASK & $07       ; bitwise AND
        mvi a, MASK | $10       ; bitwise OR
        mvi a, 1 << 3           ; shift left
        mvi a, $80 >> 2         ; shift right
        mvi a, 10 + 5           ; addition
        mvi a, 20 - 8           ; subtraction
        mvi a, 3 * 4            ; multiplication
        mvi a, 100 / 5          ; division
        mvi a, ~$f0             ; bitwise NOT (result: $0f)
        mvi a, (-1) & $ff       ; negative masked to byte (result: $ff)
        mvi a, (5 > 3) ? $aa : $55  ; ternary
        
        lxi h, TABLE            ; 16-bit label
        lxi h, PAGE + $34       ; 16-bit expression
        lxi h, TABLE + (OFFSET * 2)  ; complex expression
        lxi d, $1000 + $234     ; direct arithmetic

; Combining hi/lo bytes needs intermediate constants
TABLE_HI        .const  >TABLE
TABLE_LO        .const  <TABLE
TABLE_COMBINED  .const  (TABLE_HI << 8) | TABLE_LO  ; same as TABLE

        lxi b, TABLE_COMBINED   ; reconstructed from hi/lo

; ============================================================================
; 8085 DIRECT/ABSOLUTE MODE: LDA addr / STA addr / LHLD / SHLD / JMP / CALL
; ============================================================================
i8085_direct
        lda TABLE               ; label
        lda PAGE + OFFSET       ; expression
        lda TABLE + (BASE * 2)  ; complex expression
        sta TABLE + $10         ; store with offset
        
        lhld TABLE              ; load HL direct
        lhld PAGE + $80         ; with expression
        shld TABLE + $100       ; store HL direct
        
        jmp jump_target         ; forward reference
        jmp TABLE               ; label as address
        jmp PAGE + $50          ; expression as address
        
        call call_target        ; forward reference
        call TABLE + $200       ; expression as address

jump_target
        nop
call_target
        ret

; ============================================================================
; 8085 RELATIVE EXPRESSIONS (using $ for current address)
; ============================================================================
i8085_relative
        jmp $+3                 ; jump forward 3 bytes (skip next instruction)
        nop
        jmp $-3                 ; jump backward
loop_here
        jmp loop_here           ; label reference
        jmp $                   ; infinite loop (jump to self)

; ============================================================================
; 8085 RST VECTORS (RST only takes literal 0-7)
; ============================================================================
i8085_rst
        rst 0                   ; RST 0
        rst 1                   ; RST 1
        rst 2                   ; RST 2
        rst 3                   ; RST 3
        rst 4                   ; RST 4
        rst 5                   ; RST 5
        rst 6                   ; RST 6
        rst 7                   ; RST 7

; ============================================================================
; 8085 I/O with expressions
; ============================================================================
IO_BASE         .const  $10
IO_DATA         .const  IO_BASE + 0
IO_STATUS       .const  IO_BASE + 1
IO_CONTROL      .const  IO_BASE + 2

i8085_io
        in IO_DATA              ; input from label
        in IO_BASE + 1          ; input from expression
        out IO_STATUS           ; output to label
        out IO_BASE + 2         ; output to expression

; ============================================================================
; Data directives with expressions
; ============================================================================
i8085_data
        .byte num_dec, num_hex, num_hex_pref
        .byte num_bin, num_bin_pref, num_bin_long  ; binary formats
        .byte num_oct, num_oct_q
        .byte hi_byte, lo_byte
        .byte not_zero, not_one
        .byte shift_l, shift_r
        .byte cmp_eq, cmp_ne, cmp_le, cmp_lt, cmp_ge, cmp_gt
        .byte bit_and, bit_or, bit_xor
        .byte log_and, log_or, log_xor
        .byte ternary1, ternary2, ternary3
        .byte char_a
        .byte BASE + OFFSET     ; expression in .byte
        .byte (TABLE >> 8)      ; high byte of word
        .byte (TABLE & $ff)     ; low byte of word
        .byte num_sep_bin       ; binary with digit separators
        .byte num_sep_suf       ; suffix binary with separators
        
        .word bit_not, neg_one, pow1, pow2
        .word char_ab
        .word TABLE             ; label in .word
        .word PAGE + $100       ; expression in .word
        .word TABLE + (OFFSET << 1)  ; complex expression
        .word num_sep_dec       ; decimal with digit separators (truncated)
        .word num_sep_hex       ; hex with digit separators

; ============================================================================
; PART 2: 6502 FAMILY - Expressions in addressing modes
; ============================================================================
        .cpu 6502
        .org $0400

; --- 6502-specific constants ---
ZP_BASE         .const  $20
ZP_OFFSET       .const  $08
ABS_BASE        .const  $1000
VECTOR          .const  $FFFE

; ============================================================================
; 6502 IMMEDIATE MODE: LDA #imm
; ============================================================================
m6502_imm
        lda #BASE               ; label
        lda #BASE + OFFSET      ; expression
        lda #>ABS_BASE          ; high byte
        lda #<ABS_BASE          ; low byte
        lda #MASK & $07         ; bitwise AND
        lda #MASK | $10         ; bitwise OR
        lda #1 << 3             ; shift left
        lda #$80 >> 2           ; shift right
        lda #10 + 5             ; addition
        lda #20 - 8             ; subtraction
        lda #3 * 4              ; multiplication
        lda #100 / 5            ; division
        lda #(~$f0) & $ff       ; bitwise NOT masked to byte
        lda #(-1) & $ff         ; negative masked to byte ($ff)
        lda #(5 > 3) ? $aa : $55    ; ternary
        
        ldx #ZP_BASE            ; X immediate
        ldy #ZP_OFFSET          ; Y immediate
        ldx #(TABLE >> 8) & $ff ; high byte of table
        ldy #TABLE & $ff        ; low byte of table

; ============================================================================
; 6502 ZERO PAGE MODE: LDA $nn
; ============================================================================
m6502_zp
        lda ZP_BASE             ; label (zero page)
        lda ZP_BASE + ZP_OFFSET ; expression
        sta ZP_BASE + 1         ; store with offset
        ldx ZP_BASE + 2         ; load X
        ldy ZP_BASE + 3         ; load Y
        adc ZP_BASE + 4         ; add with carry
        sbc ZP_BASE + 5         ; subtract with borrow
        and ZP_BASE + 6         ; AND
        ora ZP_BASE + 7         ; OR
        eor ZP_BASE + 8         ; XOR
        inc ZP_BASE + 9         ; increment memory
        dec ZP_BASE + 10        ; decrement memory
        bit ZP_BASE + 11        ; bit test
        asl ZP_BASE + 12        ; arithmetic shift left
        lsr ZP_BASE + 13        ; logical shift right
        rol ZP_BASE + 14        ; rotate left
        ror ZP_BASE + 15        ; rotate right

; ============================================================================
; 6502 ZERO PAGE,X MODE: LDA $nn,X
; ============================================================================
ZP_DOUBLED      .const  ZP_OFFSET * 2   ; pre-calculate expression

m6502_zpx
        lda ZP_BASE,x           ; label
        lda ZP_BASE + 4,x       ; expression
        sta ZP_BASE + 8,x       ; store
        adc ZP_BASE + 12,x      ; add
        and ZP_BASE + $10,x     ; AND with hex offset
        ora ZP_DOUBLED,x        ; pre-defined expression
        inc ZP_BASE,x           ; increment
        dec ZP_BASE + 1,x       ; decrement with offset
        asl ZP_BASE + 2,x       ; shift
        lsr ZP_BASE + 3,x       ; shift

; ============================================================================
; 6502 ZERO PAGE,Y MODE: LDX $nn,Y
; ============================================================================
m6502_zpy
        ldx ZP_BASE,y           ; label
        ldx ZP_BASE + 4,y       ; expression
        stx ZP_BASE + 8,y       ; store

; ============================================================================
; 6502 ABSOLUTE MODE: LDA $nnnn
; ============================================================================
m6502_abs
        lda ABS_BASE            ; label
        lda ABS_BASE + $100     ; expression
        lda PAGE + OFFSET       ; labels from 8085 section
        sta ABS_BASE + $200     ; store
        ldx TABLE               ; load X absolute
        ldy TABLE + $10         ; load Y with offset
        jmp abs_target          ; forward reference
        jmp ABS_BASE + $50      ; expression
        jsr abs_sub             ; subroutine call
        jsr TABLE + $100        ; expression as address

abs_target
        nop
abs_sub
        rts

; ============================================================================
; 6502 ABSOLUTE,X MODE: LDA $nnnn,X
; ============================================================================
m6502_absx
        lda ABS_BASE,x          ; label
        lda ABS_BASE + $100,x   ; expression
        lda TABLE + (OFFSET * 4),x  ; complex expression
        sta ABS_BASE + $200,x   ; store
        adc PAGE,x              ; add
        and TABLE,x             ; AND

; ============================================================================
; 6502 ABSOLUTE,Y MODE: LDA $nnnn,Y
; ============================================================================
m6502_absy
        lda ABS_BASE,y          ; label
        lda ABS_BASE + $100,y   ; expression
        sta ABS_BASE + $200,y   ; store
        ldx TABLE,y             ; load X absolute,Y
        adc PAGE,y              ; add

; ============================================================================
; 6502 INDIRECT MODE: JMP ($nnnn)
; ============================================================================
m6502_ind
        jmp (VECTOR)            ; indirect through label
        jmp (ABS_BASE + $10)    ; indirect through expression
        jmp (TABLE)             ; indirect through table

; ============================================================================
; 6502 INDEXED INDIRECT MODE: LDA ($nn,X)
; ============================================================================
m6502_indx
        lda (ZP_BASE,x)         ; label
        lda (ZP_BASE + 4,x)     ; expression
        sta (ZP_BASE + 8,x)     ; store
        adc (ZP_OFFSET * 2,x)   ; expression as base
        and (ZP_BASE,x)         ; AND
        ora (ZP_BASE + $10,x)   ; OR
        eor (ZP_BASE + $20,x)   ; XOR
        cmp (ZP_BASE + $30,x)   ; compare

; ============================================================================
; 6502 INDIRECT INDEXED MODE: LDA ($nn),Y
; ============================================================================
m6502_indy
        lda (ZP_BASE),y         ; label
        lda (ZP_BASE + 4),y     ; expression
        sta (ZP_BASE + 8),y     ; store
        adc (ZP_OFFSET * 2),y   ; expression as base
        and (ZP_BASE),y         ; AND
        ora (ZP_BASE + $10),y   ; OR
        eor (ZP_BASE + $20),y   ; XOR
        cmp (ZP_BASE + $30),y   ; compare

; ============================================================================
; 6502 RELATIVE MODE: Branches with expressions
; ============================================================================
m6502_rel
branch_here
        bne branch_here         ; backward branch to label
        beq $+2                 ; skip next (branch offset 0)
        bcc $+4                 ; skip 2 bytes forward
        bcs branch_fwd          ; forward reference
        bmi $-2                 ; backward branch
        bpl branch_here         ; backward to label
        bvc $+6                 ; longer forward skip
        bvs branch_fwd          ; forward reference
branch_fwd
        nop

; ============================================================================
; 65C02-ONLY ADDRESSING MODES with expressions
; ============================================================================
        .cpu 65c02

m65c02_modes
; Zero Page Indirect: LDA ($nn)
        lda (ZP_BASE)           ; label
        lda (ZP_BASE + 4)       ; expression
        sta (ZP_BASE + 8)       ; store
        adc (ZP_OFFSET * 2)     ; expression as base

; Absolute Indexed Indirect: JMP ($nnnn,X)
        jmp (ABS_BASE,x)        ; label
        jmp (TABLE + $100,x)    ; expression
        jmp (VECTOR,x)          ; vector table indexed

; ============================================================================
; 6502 Data section with expressions
; ============================================================================
m6502_data
        .byte ZP_BASE           ; label
        .byte ZP_BASE + ZP_OFFSET   ; expression
        .byte >ABS_BASE         ; high byte
        .byte <ABS_BASE         ; low byte
        .byte MASK & $0f        ; masked value
        .byte 1 << 4            ; shifted
        .byte ~$f0 & $ff        ; NOT masked to byte
        
        .word ABS_BASE          ; label
        .word ABS_BASE + $100   ; expression
        .word TABLE + (OFFSET * 2)  ; complex expression
        .word VECTOR            ; vector address

; ============================================================================
; PART 3: Expression edge cases and complex expressions
; ============================================================================
        .cpu 8085
        .org $0800

; Nested expressions
nested1         .const  ((1 + 2) * (3 + 4))     ; = 21
nested2         .const  (((1 << 2) | 8) & $0f)  ; = 12
nested3         .const  (5 > 3) ? ((2 + 3) * 2) : 0  ; = 10

; Chained operations
chain1          .const  1 + 2 + 3 + 4 + 5       ; = 15
chain2          .const  $ff & $0f | $30         ; = $3f
chain3          .const  1 << 2 << 1             ; = 8

; Labels referencing labels
derived1        .const  BASE * 2                ; = $20
derived2        .const  derived1 + OFFSET       ; = $25
derived3        .const  derived2 | $80          ; = $a5

; Using expressions in instructions
        mvi a, nested1
        mvi b, nested2
        mvi c, nested3
        mvi d, chain1
        mvi e, chain2
        mvi h, derived1
        mvi l, derived2

; Address arithmetic with current location
addr_base
        .byte $+0 - addr_base   ; offset 0
        .byte $+0 - addr_base   ; offset 1
        .byte $+0 - addr_base   ; offset 2
        .byte $+0 - addr_base   ; offset 3

; Expression results in data
        .byte nested1, nested2, nested3
        .byte chain1, chain2, chain3
        .byte derived1, derived2, derived3

        .word addr_base         ; reference to label
        .word addr_base + 4     ; label + offset
        .word $ - addr_base     ; current offset from label

        .end
