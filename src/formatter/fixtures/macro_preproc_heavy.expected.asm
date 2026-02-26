.macro INC_A
            inr a
.endmacro
.ifdef FLAG
INC_A ; macro call
.endif
