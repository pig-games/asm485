; Test and demonstrate assembly errors
; lines marked with ERR are detected by the assenbler
; lines marked as *ERR should be detected, but are currently not

; constants
symd1   .const 55          ; decimal constant
symd2   .const 5X5         ; ERR: bad decimal constant
symd3   .const 55X         ; ERR: bad decimal constant
symh1   .const 5A5h        ; hex constant
symh2   .const 5A5         ; ERR: missing H for hex constant
symh3   .const ffffH       ; ERR: hex must start with numeric
symh4   .const 0ffffH      ; Hex with leading zero
symb1   .const 01100110b   ; Binary constant
symb2   .const 01101210b   ; ERR: bad binary constant
symq1   .const 123q        ; octal constant
symq2   .const 128o        ; ERR: bad octal constant

bah     .const 77h
bad:    .byte  "where is the .end  ; ERR: unterminated string
special: .byte  "\t\n\r",bah,beh, bad  ; ERR: undefined symbol

; column zero
LABEL1:                 ; label can start in column 0
LABEL2: MOV   C,A       ; label with instruction also OK
NAME1   .const   7         ; name can start in column zero
123                     ; ERR: not name or label
"abc"                   ; ERR: not name or label
+                       ; ERR: not name or label
mov h,l                 ; ERR: instruction can't start in column zero

; extra information on line and extra/incorrect arguments
        nop     SP      ; ERR: extra register argument
        nop     d,e     ; ERR: multiple extra registers
        nop     str     ; ERR: extra expression argument
        nop     12XX    ; ERR: extra characters
        MOV     A       ; ERR: missing second register
        MOV     A,4     ; ERR: missing second register
        MVI     B,A     ; ERR: second arg should be expression
        JMP     SP      ; ERR: first arg should be expression
        JZ              ; ERR: missing arg
        MVI     b,1+2+  ; ERR: extra chars in expression

; RST instructions
        RST     0       ; OK
        RST     A       ; ERR: must be number
RNUM    .const     1
        RST     RNUM    ; ERR: expression not allowed
        RST     1+1     ; ERR: expression not allowed
        RST     7       ; OK
        RST     9       ; ERR: RST number must be 0..7

; characters in expressions      
        mvi     b,'P'   ; single char is a byte
        lxi     d,'QR'  ; two chars is a sixteen bit value
        mvi     e,'abc' ; ERR: Can't use string in expression
        lxi     b,'a'*'B' ; weird, but legal


; math
var1    .const     23 / 0  ; ERR: divide by zero
var2:   .word      255 + 10; OK as a 16 bit value
var3:   .byte      255 + 10; *ERR: 8 bit constant overflow


; name/label mismatch
nam1    .word  7           ; ERR: .word uses label, not name
nam2    .ds  10          ; ERR: .ds uses label, not name
nam3    jmp 0           ; ERR: instruction uses label, not name
lab1:   .const 6           ; ERR: .const uses name, not label
lab2:   .var 8           ; ERR: .var uses name, not label

; redeine symbols and labels
equ1    .const 1           ; OK
equ1    .const 2           ; ERR: redefined symbol with .const
set1    .var 1           ; OK
set1    .var 2           ; OK, can redefine .var
set1    .const 3           ; should be an error to mix set and equ
set1    .var 4           ; OK, can redefine .var
equ2    .const 2           ; OK
equ2    .var 3           ; ERR: cannot redefine .const

lab3:   jmp 0           ; OK
lab3:   jmp 1           ; ERR: label redefined
lab4:   jmp 2           ; OK


; Conditional directives
YES         .const 1
TRUE        .const 0ffffh
NO          .const 0
FALSE       .const 0

                .org 5000h
; ERR - missing IF
        .elseif YES                     ; ERR - missing IF
        .else                           ; ERR - missing IF
        .endif                          ; ERR - missing IF


; ERR - multiple ELSE
        .if FALSE                       ; OK
        .else                           ; OK
        .else                           ; ERR - multiple ELSE
        .endif


; ERR - ELSEIF follows ELSE
        .if FALSE                       ; OK
        .else                           ; OK
        .elseif TRUE                    ; ERR - ELSEIF follows ELSE
        .endif
       

; ERR - missing ENDIF
        .if FALSE || 3+1 == 4           ; OK
                lxi h,0beefh
