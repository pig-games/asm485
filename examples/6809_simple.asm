; Basic Motorola 6809 smoke fixture
.cpu m6809
.org $1000

start:
    NOP
    LDA #$2A
    LDD #$1234
    RTS
