; Typed struct literals assigned to const/var symbols with member value access.
.cpu 6502

Point .struct
x .byte ?
y .byte ?
.endstruct

p0 .const Point { x: 24, y: 50 }
p1 .var Point { x: 40, y: 60 }

.byte p0.x
.byte p0.y
.byte p1.x
.byte p1.y

p1 .set Point { x: 41, y: 61 }

.byte p1.x
.byte p1.y
