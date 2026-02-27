; Motorola 6809 register-transfer and stack-list fixture
.cpu m6809
.org $1000

start:
    TFR A,B
    EXG X,Y
    PSHS CC,A,B,X,Y,U,PC
    PULS CC,A,B,X,Y,U,PC
    PSHU CC,A,B,X,Y,S,PC
    PULU CC,A,B,X,Y,S,PC
    RTS
