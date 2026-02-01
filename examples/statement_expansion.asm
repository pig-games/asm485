; Demonstrate .statement expansion.

.statement LOAD byte:val
    .byte .val
.endstatement

.statement lda "["[{byte:val}]"],y"
    .byte .val
.endstatement

.statement move.b char:dst[{byte:dstnum}] "," char:src[{byte:srcnum}]
    .byte 'b'
    .byte '.dst', .dstnum
    .byte '.src', .srcnum
.endstatement

.statement move.l char:dst[{byte:dstnum}] "," char:src[{byte:srcnum}]
    .byte 'l'
    .byte '.dst', .dstnum
    .byte '.src', .srcnum
.endstatement

start:
    LOAD 7
    lda [5],y
    lda [5],x
    move.b d0,d2
    move.l d0, d2
