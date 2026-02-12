; Namespace scopes and 64tass-compatible close aliases

        .org 1000h

VALUE   .const 1

        .namespace outer
        .namespace inner
VALUE   .const 5
        .endn
        .endnamespace

SCOPE   .block
LOCAL   .const 9
        .bend

        .word VALUE
        .word outer.inner.VALUE
        .word SCOPE.LOCAL
        .end
