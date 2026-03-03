; Ranges, lists, indexing, and .len.
.cpu 6502

values = {2, 4, 6, 8}

.byte .len(values)
.byte values[2]

.for n in 0..=6:3
    .byte n
.endfor
