; Expression syntax coverage for 64tass-style operators and literals
        .org     0000h

; numeric literals: decimal, suffixes, prefixed
num_dec         .const     123
num_hex         .const     0a6h
num_hex_pref    .const     $1f
num_bin         .const     1010b
num_bin_pref    .const     %1010
num_oct         .const     17o
num_oct_q       .const     17q

; unary operators and bytes
hi_byte         .const     >1234h
lo_byte         .const     <1234h
not_zero        .const     !0
not_one         .const     !1
bit_not         .const     ~00ffh
neg_one         .const     -1

; arithmetic, power, shifts
pow1            .const     2 ** 3
pow2            .const     3 ** 2 ** 2
shift_l         .const     1 << 4
shift_r         .const     0ffh >> 4

; comparisons
cmp_eq          .const     (3 == 3)
cmp_ne          .const     (3 != 4)
cmp_ne_alt      .const     (3 <> 4)
cmp_le          .const     (3 <= 4)
cmp_lt          .const     (3 < 4)
cmp_ge          .const     (4 >= 3)
cmp_gt          .const     (4 > 3)
cmp_eq_alias    .const     (4 = 4)

; bitwise and logical
bit_and         .const     (0f0h & 00fh)
bit_or          .const     (0f0h | 00fh)
bit_xor         .const     (0f0h ^ 00fh)
log_and         .const     (2 && 3)
log_or          .const     (0 || 3)
log_xor         .const     (2 ^^ 3)

; ternary
ternary1        .const     0 ? 1 : 2
ternary2        .const     5 ? 7 : 9
ternary3        .const     (0 || 1) ? (2 + 3) : (4 + 5)

; string constants in expressions
char_a          .const     'A'
char_ab         .const     'AB'

; data emissions
        .byte      num_dec, num_hex, num_hex_pref, num_bin, num_bin_pref
        .byte      num_oct, num_oct_q, hi_byte, lo_byte, not_zero, not_one
        .word      bit_not, neg_one, pow1, pow2
        .byte      shift_l, shift_r
        .byte      cmp_eq, cmp_ne, cmp_ne_alt, cmp_le, cmp_lt, cmp_ge, cmp_gt, cmp_eq_alias
        .byte      bit_and, bit_or, bit_xor, log_and, log_or, log_xor
        .byte      ternary1, ternary2, ternary3
        .byte      char_a
        .word      char_ab
