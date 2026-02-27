; Motorola 6809 branch fixture
.cpu m6809
.org $1000

start:
    BCC near
    BRN end
near:
    BNE end
    LBRA far
end:
    RTS
far:
    RTS
