; Condition-based loop.
.cpu 6502
.org 0

.while $ < 4
    .byte $ff
.endwhile
