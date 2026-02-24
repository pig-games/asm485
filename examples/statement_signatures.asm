; Demonstrate statement signature syntax.

.statement move.b char:dst "," char:src
    nop
.endstatement

.statement sta "[" byte:a ","[{char:reg}]
.endstatement

start
    nop
