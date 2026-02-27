; Hitachi HD6309 extension fixture
.cpu hd6309
.org $1000

start:
    SEXW
    CLRD
    CLRW
    CLRE
    CLRF
    LDA #$11
    RTS
