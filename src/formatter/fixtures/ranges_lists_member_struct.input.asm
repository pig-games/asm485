Point .struct
x .byte ?
y .byte ?
.endstruct
p0 .const Point {x:1,y:2}
points .bfor i in 0..=2
x .byte i
y .byte i+1
.endfor
 .byte p0.x,points[1].y,.len({1,2,3}),0..=6:2
