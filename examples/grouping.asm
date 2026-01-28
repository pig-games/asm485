; grouping.asm - Test generic grouping functionality
; This ensures that (1+2) is evaluated as math, not indirect addressing
    .org $100
    MVI A, (1+2)
    ADI (5*2)
