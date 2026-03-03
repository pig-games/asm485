; Struct type assigned to a variable symbol and accessed via member expressions.
.cpu 6502

Point .struct
x .byte ?
y .word ?
.endstruct

pt .var Point

; Point size, then offsets via the struct-valued variable.
.byte Point
.byte pt.x
.byte pt.y
