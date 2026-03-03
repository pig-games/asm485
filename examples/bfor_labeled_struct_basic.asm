; Scoped repetition with inferred struct fields and indexed member access.
.cpu 6502

Point .struct
x .byte ?
y .byte ?
.endstruct

points .bfor i in 0..=2
x .byte i
y .byte i + 10
.endfor

.word points[1].x
.word points[1].y
