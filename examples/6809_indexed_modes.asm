; Motorola 6809 indexed-mode baseline fixture
.cpu m6809
.org $1000

start:
    LDA $20,X
    LDA A,Y
    LDB -1,S
    LDD 16,U
    LDA 4,PC
    RTS
