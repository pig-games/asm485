; Labels inside unscoped .while are rejected.
.org 0
.while $ < 1
item .byte 1
.endwhile
