; Iterable .for loop over a list literal.
.cpu 6502

nums = {1, 3, 5, 7}

.for value in nums
    .byte value
.endfor
