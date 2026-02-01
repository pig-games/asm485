; Conditional assembly (.if/.elseif/.else/.endif) coverage
        .org     2000h

TRUE    .const     1
FALSE   .const     0

; simple if/else
        .if TRUE
                .byte 1
        .else
                .byte 2
        .endif

; elseif chain
        .if 0
                .byte 3
        .elseif 0
                .byte 4
        .elseif 5
                .byte 5
        .else
                .byte 6
        .endif

; nested conditionals
        .if 1
                .if 0
                        .byte 7
                .else
                        .byte 8
                .endif
        .else
                .byte 9
        .endif

; labels on conditionals
LABIF:  .if TRUE
                .byte 10
LABELSE:.else
                .byte 11
LABEND: .endif

; match/case/default
        .match 2
        .case 1
                .byte 12
        .case 2, 3
                .byte 13
        .default
                .byte 14
        .endmatch

        .match 9
        .case 1, 2
                .byte 15
        .default
                .byte 16
        .endmatch
