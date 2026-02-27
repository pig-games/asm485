; Motorola 6809 indexed-mode baseline fixture
.cpu m6809
.org $1000

start:
    LDA $20,X
    LDA A,Y
    LDA [$20,X]
    LDA [A,X]
    LDA [$1234]
    LDA [4,PC]
    LDB -1,S
    STB A,X
    LDD 16,U
    JSR $20,X
    LDA 4,PC
    RTS
