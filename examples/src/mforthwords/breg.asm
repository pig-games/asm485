; Copyright (c) 2009-2010, Michael Alyn Miller <malyn@strangeGizmo.com>.
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are met:
;
; 1. Redistributions of source code must retain the above copyright notice
;    unmodified, this list of conditions, and the following disclaimer.
; 2. Redistributions in binary form must reproduce the above copyright notice,
;    this list of conditions and the following disclaimer in the documentation
;    and/or other materials provided with the distribution.
; 3. Neither the name of Michael Alyn Miller nor the names of the contributors
;    to this software may be used to endorse or promote products derived from
;    this software without specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND ANY
; EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
; DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
; (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
; ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
; THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


; ======================================================================
; B ("byte") Register Words
; ======================================================================

; ----------------------------------------------------------------------
; 'B [MFORTH] ( -- c-addr)
;
; Push the address of the B register (a USER variable) to the stack.

            .linkTo link_breg,0,2,'B',"\'"
tickb JMP     douser
            .byte   userb


; ----------------------------------------------------------------------
; 'Bend [MFORTH] ( -- c-addr)
;
; Push the address of the Bend register (a USER variable) to the stack.

            .linkTo tickb,0,5,'d',"neB\'"
tickbend JMP     douser
            .byte   userbend


; ----------------------------------------------------------------------
; 2>B [MFORTH] "two-to-b" ( c-addr u -- )
;
; Pop an address and length from the stack and store the range in B.
;
; ---
; : 2>B  ( c-addr u --)   OVER + 'Bend !  'B ! ;

            .linkTo tickbend,0,3,'B',">2"
twotob JMP     enter
            .word   over,plus,tickbend,store,tickb,store,exit


; ----------------------------------------------------------------------
; >B [MFORTH] "to-b" ( c-addr -- )
;
; Pop an address from the stack and put the address into the B register.
;
; ---
; : >B ( c-addr --)   'B ! ;

            .linkTo twotob,0,2,'B',">"
tob JMP     enter
            .word   tickb,store,exit


; ----------------------------------------------------------------------
; ?ENDB [MFORTH] "question-end-b"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( flag -- )
;   Continue execution immediately following the innermost syntactically
;   enclosing FORB ... NEXTB if flag is true.  Otherwise continue execution
;   at the next instruction.
;
; ---
; ?ENDB   POSTPONE IF
;   ['] branch COMPILE,  HERE  'PREVENDB @ ,  'PREVENDB !
;   POSTPONE THEN ; IMMEDIATE

            .linkTo tob,1,5,'B',"DNE?"
qendb JMP     enter
            .word   if,lit,branch,compilecomma
            .word   here,lit,tickprevendb,fetch,comma,lit,tickprevendb,store
            .word   then,exit


; ----------------------------------------------------------------------
; B [MFORTH] ( -- c-addr)
;
; Push the B register to the stack.
;
; ---
; : B ( -- c-addr)  'B @ ;

            .linkTo0 qendb,0,1,'B'
b MOV     H,B
            MVI     L,userb
            MOV     A,M         ; Load LSB of cell value into A
            INX     H           ; Increment to MSB of the cell value
            MOV     H,M         ; Load MSB of the cell value into H
            MOV     L,A         ; Move LSB of cell value from A to L
            PUSH    H           ; Push cell value onto stack.
            .next


; ----------------------------------------------------------------------
; B! [MFORTH] "b-store" ( c -- )
;
; Pop a byte from the stack and store it at B.
;
; ---
; : B! (c --)   B C! ;

            .linkTo B,0,2,'!',"B"
bstore MOV     H,B
            MVI     L,userb
            MOV     A,M         ; Load LSB of cell value into A
            INX     H           ; Increment to MSB of the cell value
            MOV     H,M         ; Load MSB of the cell value into H
            MOV     L,A         ; Move LSB of cell value from A to L
            XTHL                ; Get c into L,
            MOV     A,L         ; ..then move c into A,
            POP     H           ; ..restore store HL.
            MOV     M,A         ; ..and store c at HL.
            .next


; ----------------------------------------------------------------------
; B!+ [MFORTH] "b-store-plus" ( c -- )
;
; Pop a byte from the stack, store it at B, then increment the B register
; by one (byte address location).
;
; ---
; : B!+ ( c --)   B! B+ ;

            .linkTo bstore,0,3,'+',"!B"
bstoreplus JMP     enter
            .word   bstore,bplus,exit


; ----------------------------------------------------------------------
; B# [MFORTH] "b-number" ( -- u )
;
; Push the number of bytes remaining in the range defined by B.
;
; ---
; : B# ( -- u)   'Bend @  B  - ;

            .linkTo bstoreplus,0,2,'#',"B"
bnumber PUSH    B
            MOV     H,B
            MVI     L,userb
            MOV     C,M         ; Load LSB of cell value into C
            INX     H           ; Increment to MSB of the cell value
            MOV     B,M         ; Load MSB of the cell value into B.
            MVI     L,userbend
            MOV     A,M         ; Load LSB of cell value into A
            INX     H           ; Increment to MSB of the cell value
            MOV     H,M         ; Load MSB of the cell value into H
            MOV     L,A         ; Move LSB of cell value from A to L
            .byte 08H
            XTHL
            MOV     B,H
            MOV     C,L
            .next


; ----------------------------------------------------------------------
; B+ [MFORTH] "b-plus" ( -- c-addr)
;
; Increment the B register by one (byte address location).
;
; ---
; : B+ ( --)  1 CHARS 'B +! ;

            .linkTo bnumber,0,2,'+',"B"
bplus MOV     H,B         ; Get the address of the B user variable
            MVI     L,userb     ; ..into HL.
            INR     M           ; Increment the B user variable;
            JNZ     _bplusdone  ; ..we're done if the low byte didn't roll.
            INX     H           ; Otherwise increment to the high byte
            INR     M           ; ..and propagate the overflow.
_bplusdone .next


; ----------------------------------------------------------------------
; B? [MFORTH] "b-question" ( -- flag )
;
; flag is true if and only if there are more bytes in B.
;
; ---
; : B? ( -- f)   B# 0 > ;

            .linkTo bplus,0,2,'?',"B"
bques PUSH    B
            MOV     H,B
            MVI     L,userb
            MOV     C,M         ; Load LSB of cell value into C
            INX     H           ; Increment to MSB of the cell value
            MOV     B,M         ; Load MSB of the cell value into B.
            MVI     L,userbend
            MOV     A,M         ; Load LSB of cell value into A
            INX     H           ; Increment to MSB of the cell value
            MOV     H,M         ; Load MSB of the cell value into H
            MOV     L,A         ; Move LSB of cell value from A to L
            .byte 08H
            JZ      _bquesdone  ; Leave zero in HL and we're done; otherwise
            LXI     H,0FFFFH    ; ..put true in HL.
_bquesdone XTHL
            MOV     B,H
            MOV     C,L
            .next


; ----------------------------------------------------------------------
; B@ [MFORTH] "b-fetch" ( -- c-addr)
;
; Fetch the byte at B.
;
; ---
; : B@ ( -- c)   B C@ ;

            .linkTo bques,0,2,'@',"B"
bfetch MOV     H,B
            MVI     L,userb
            MOV     A,M         ; Load LSB of cell value into A
            INX     H           ; Increment to MSB of the cell value
            MOV     H,M         ; Load MSB of the cell value into H
            MOV     L,A         ; Move LSB of cell value from A to L
            MOV     A,M         ; Load target byte into A,
            MOV     L,A         ; ..put target byte into L,
            MVI     H,0         ; ..clear the high byte,
            PUSH    H           ; ..and then push the byte to the stack.
            .next


; ----------------------------------------------------------------------
; B@+ [MFORTH] "b-fetch-plus" ( -- c )
;
; Fetch the byte at B, then increment the B register by one (byte address
; location.
;
; ---
; : B@+ ( -- c)   B@ B+ ;

            .linkTo bfetch,0,3,'+',"@B"
bfetchplus JMP     enter
            .word   bfetch,bplus,exit


; ----------------------------------------------------------------------
; FORB [MFORTH] "for-b"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: -- forb-sys )
;   Place forb-sys onto the control-flow stack.  Append the run-time
;   semantics given below to the current definition.  The semantics are
;   incomplete until resolved by a consumer of forb-sys such as NEXTB.
;
; Run-time: ( -- )
;   Set up a loop that iterates over the bytes from 'B to 'Bend.
;
; ---
; forb-sys in MFORTH is ( forb-orig ).  ?ENDB locations chain from the most
; recent ?ENDB to the oldest ?ENDB and then to zero, which signifies the
; end of the ?ENDB list.  NEXTB goes through the ?ENDB list and fixes up
; the addresses.
;
; : FORB   0 'PREVENDB !  POSTPONE BEGIN
;   POSTPONE B# POSTPONE 0= POSTPONE ?ENDB
; ; IMMEDIATE

            .linkTo bfetchplus,1,4,'B',"ROF"
forb JMP     enter
            .word   zero,lit,tickprevendb,store,begin
            .word   lit,bnumber,compilecomma,lit,zeroequals,compilecomma,qendb
            .word   exit


; ----------------------------------------------------------------------
; NEXTB [MFORTH] "next-b"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: dest -- )
;   Append the run-time semantics given below to the current definition.
;   Resolve the destination of all unresolved occurrences of ?ENDB between
;   the location given by dest and the next location for a transfer of
;   control, to execute the words following the NEXTB.
;
; Run-time: ( -- )
;   Increment 'B and continue execution at the location specified by dest.
;
; ---
; NEXTB   POSTPONE B+ POSTPONE AGAIN  'PREVENDB @ HERE>CHAIN ; IMMEDIATE

            .linkTo forb,1,5,'B',"TXEN"
last_breg
nextb JMP     enter
            .word   lit,bplus,compilecomma,again
            .word   lit,tickprevendb,fetch,heretochain,exit
