; Scope directives and qualified symbol references

        .org 1000h

GLOBAL  .const 1

OUTER   .block
INNER   .block
VAL     .const 5
        .endblock
        .endblock

SHADOW  .block
GLOBAL  .const 2
        .word GLOBAL         ; resolves to SHADOW.GLOBAL
        .endblock

        .word GLOBAL         ; resolves to GLOBAL
        .word OUTER.INNER.VAL
        .end
