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
; CORE Words
; ======================================================================

; ----------------------------------------------------------------------
; ! [CORE] 6.1.0010 "store" ( x a-addr -- )
;
; Store x at a-addr.

            .linkTo0 link_core,0,1,'!'
store .saveDe
            POP     D           ; Pop a-addr
            POP     H           ; Pop x.
            .byte 0D9H                ; Store x into a-addr.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; # [CORE] 6.1.0030 "number-sign" ( ud1 -- ud2 )
;
; Divide ud1 by the number in BASE giving the quotient ud2 and the remainder
; n.  (n is the least-significant digit of ud1.)  Convert n to external form
; and add the resulting character to the beginning of the pictured numeric
; output string.  An ambiguous condition exists if # executes outside of a
; <# #> delimited number conversion.
;
; ---
; : # ( ud1 -- ud2 )   BASE @ UD/MOD ROT >digit HOLD ;

            .linkTo0 store,0,1,'#'
numsign JMP     enter
            .word   base,fetch,udslashmod,rot,todigit,hold
            .word   exit


; ----------------------------------------------------------------------
; #> [CORE] 6.1.0040 "number-sign-greater" ( xd -- c-addr u )
;
; Drop xd.  Make the pictured numeric output string available as a character
; string.  c-addr and u specify the resulting character string.  A program
; may replace characters within the string.
;
; ---
; : #> ( xd -- c-addr u ) DROP DROP  HLD @  HERE HLDEND +  OVER - ;

            .linkTo numsign,0,2,'>',"#"
numsigngrtr JMP     enter
            .word   drop,drop,hld,fetch,here,lit,hldend,plus,over,minus
            .word   exit


; ----------------------------------------------------------------------
; #S [CORE] 6.1.0050 "number-sign-s" ( ud1 -- ud2 )
;
; Convert one digit of ud1 according to the rule for #.  Continue conversion
; until the quotient is zero.  ud2 is zero.  An ambiguous condition exists
; if #S executes outside of a <# #> delimited number conversion.
;
; ---
; : #S ( ud1 -- 0 )   BEGIN # 2DUP OR WHILE REPEAT ;

            .linkTo numsigngrtr,0,2,'S',"#"
numsigns JMP     enter
_numsigns1 .word   numsign,twodup,or,zbranch,_numsigns2,branch,_numsigns1
_numsigns2 .word   exit


; ----------------------------------------------------------------------
; ' [CORE] 6.1.0070 "tick" ( "<spaces>name" -- xt )
;
; Skip leading space delimiters.  Parse name delimited by a space.  Find
; name and return xt, the execution token for name.  An ambiguous condition
; exists if name is not found.
;
; When interpreting, ' xyz EXECUTE is equivalent to xyz.
;
; ---
; : ' ( "<spaces>name" -- xt)
;   PARSE-WORD (FIND)  0= IF TYPE SPACE [CHAR] ? EMIT CR ABORT THEN ;

            .linkTo0 numsigns,0,1,027H
tick JMP     enter
            .word   parseword,pfind,zeroequals,zbranch,_tick1
            .word   type,space,lit,'?',emit,cr,abort
_tick1 .word   exit


; ----------------------------------------------------------------------
; ( [CORE] 6.1.0080 "paren"
;
; Compilation:
;   Perform the execution semantics given below.
;
; Execution: ( "ccc<paren>" -- )
;   Parse ccc delimited by ) (right parenthesis).  ( is an immediate word.
;   The number of characters in ccc may be zero to the number of characters
;   in the parse area.
;
; Extended by FILE:
;   When parsing from a text file, if the end of the parse area is reached
;   before a right parenthesis is found, refill the input buffer from the
;   next line of the file, set >IN to zero, and resume parsing, repeating
;   this process until either a right parenthesis is found or the end of the
;   file is reached.
;
; ---
; TODO: Need to implement the extended FILE logic.  I recommend that we modify
;       this code to use REFILL.  We could also avoid PARSE altogether and
;       just go through the input source on our own.  Note that we need to
;       rewrite this in assembly language so that we don't get hit by the
;       perf issues of processing one byte at a time in high-level code.
;
; : ( ( "ccc<quote>" --)   CHAR] ) PARSE 2DROP ;

            .linkTo0 tick,1,1,028H
paren JMP     enter
            .word   lit,029H,parse,twodrop,exit


; ----------------------------------------------------------------------
; * [CORE] 6.1.0090 "star" ( n1|u1 n2|u2 -- n3|u3 )
;
; Multiply n1|u1 by n2|u2 giving the product n3|u3.
;
; ---
; : * ( n1|u1 n2|u2 -- n3|u3 )   UM* DROP ;

            .linkTo0 paren,0,1,'*'
star JMP     enter
            .word   umstar,drop,exit


; ----------------------------------------------------------------------
; */ [CORE] 6.1.0100 "star-slash" ( n1 n2 n3 -- n4 )
;
; Multiply n1 by n2 producing the intermediate double-cell result d.
; Divide d by n3 giving the single-cell quotient n4.  An ambiguous
; condition exists if n3 is zero or if the quotient n4 lies outside the
; range of a signed number.  If d and n3 differ in sign, the
; implementation-defined result returned will be the same as that returned
; by either the phrase >R M* R> FM/MOD SWAP DROP or the phrase
; >R M* R> SM/REM SWAP DROP.
;
; ---
; : */ ( n1 n2 n3 -- n4)   */MOD NIP ;

            .linkTo star,0,2,'/',"*"
starslash JMP     enter
            .word   starslashmod,nip,exit


; ----------------------------------------------------------------------
; */MOD [CORE] 6.1.0110 "star-slash-mod" ( n1 n2 n3 -- n4 n5 )
;
; Multiply n1 by n2 producing the intermediate double-cell result d.
; Divide d by n3 producing the single-cell remainder n4 and the
; single-cell quotient n5.  An ambiguous condition exists if n3 is zero,
; or if the quotient n5 lies outside the range of a single-cell signed
; integer.  If d and n3 differ in sign, the implementation-defined result
; returned will be the same as that returned by either the phrase
; >R M* R> FM/MOD or the phrase >R M* R> SM/REM. 
;
; ---
; : */MOD ( n1 n2 n3 -- n4 n5)   >R M* R> SM/REM ;

            .linkTo starslash,0,5,'D',"OM/*"
starslashmod JMP    enter
            .word   tor,mstar,rfrom,smslashrem,exit


; ----------------------------------------------------------------------
; + [CORE] 6.1.0120 "plus" ( n1|u1 n2|u2 -- n3|u3 )
;
; Add n2|u2 to n1|u1, giving the sum n3|u3.

            .linkTo0 starslashmod,0,1,'+'
plus .saveDe
            POP     D           ; Pop n2|u2.
            POP     H           ; Pop n1|u1.
            DAD     D           ; HL=HL+DE
            PUSH    H           ; Push the result onto the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; +! [CORE] 6.1.0130 "plus-store" ( n|u a-addr -- )
;
; Add n|u to the single-cell number at a-addr.

            .linkTo plus,0,2,'!',"+"
plusstore .saveDe
            POP     D           ; Pop a-addr.
            POP     H           ; Pop n|u.
            PUSH    B           ; Save BC.
            MOV     B,H         ; Move n|u
            MOV     C,L         ; ..to BC.
            .byte 0EDH                ; Fetch the number at a-addr.
            DAD     B           ; Add n|u to the number.
            .byte 0D9H                ; Store the updated number.
            POP     B           ; Restore BC.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; +LOOP [CORE] 6.1.0140 "plus-loop"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: do-sys -- )
;   Append the run-time semantics given below to the current definition.
;   Resolve the destination of all unresolved occurrences of LEAVE between
;   the location given by do-sys and the next location for a transfer of
;   control, to execute the words following +LOOP.  
;
; Run-time: ( n -- ) ( R: loop-sys1 -- | loop-sys2 )
;   An ambiguous condition exists if the loop control parameters are
;   unavailable.  Add n to the loop index.  If the loop index did not cross
;   the boundary between the loop limit minus one and the loop limit,
;   continue execution at the beginning of the loop.  Otherwise, discard the
;   current loop control parameters and continue execution immediately
;   following the loop.
;
; ---
; +LOOP   ['] (pplusloop) END-LOOP ; IMMEDIATE

            .linkTo plusstore,1,5,'P',"OOL+"
plusloop JMP     enter
            .word   lit,pplusloop,endloop,exit


; ----------------------------------------------------------------------
; COMMA [CORE] 6.1.0150 "comma" ( x -- )
;
; Reserve one cell of data space and store x in the cell.  If the
; data-space pointer is aligned when , begins execution, it will remain
; aligned when , finishes execution.  An ambiguous condition exists if the
; data-space pointer is not aligned prior to execution of ,.
;
; ---
; : , ( x -- )   HERE !  1 CELLS ALLOT ;

            .linkTo0 plusloop,0,1,02CH
comma JMP     enter
            .word   here,store,one,cells,allot,exit


; ----------------------------------------------------------------------
; - [CORE] 6.1.0160 "minus" ( n1|u1 n2|u2 -- n3|u3 )
;
; Subtract n2|u2 from n1|u1, giving the difference n3|u3.

            .linkTo0 comma,0,1,'-'
minus .saveDe
            POP     D           ; Pop n2|u2.
            POP     H           ; Pop n1|u1.
            PUSH    B           ; Save BC.
            MOV     B,D         ; Move n2|u2
            MOV     C,E         ; ..to BC.
            .byte 08H                ; HL=HL-BC
            POP     B           ; Restore BC.
            PUSH    H           ; Push the result onto the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; . [CORE] 6.1.0180 "dot" ( n -- )
;
; Display n in free field format.
;
; ---
; : . ( n -- )
;   BASE @ 10 <>  IF U. EXIT THEN
;   DUP ABS 0 <# #S ROT SIGN #> TYPE SPACE ;

            .linkTo0 minus,0,1,'.'
dot JMP     enter
            .word   base,fetch,lit,10,notequals,zbranch,_dot1,udot,exit
_dot1 .word   dup,abs,zero,lessnumsign,numsigns,rot,sign,numsigngrtr
            .word   type,space
            .word   exit


; ----------------------------------------------------------------------
; ." [CORE] 6.1.0190 "dot-quote"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( "ccc<quote>" -- )
;   Parse ccc delimited by " (double-quote).  Append the run-time
;   semantics given below to the current definition.
;
; Run-time: ( -- )
;   Display ccc.
;
; ---
; : ." ( "ccc<quote>" --)   POSTPONE S" POSTPONE TYPE ; IMMEDIATE

            .linkTo dot,1,2,022H,"."
dotquote JMP     enter
            .word   squote,lit,type,compilecomma,exit


; ----------------------------------------------------------------------
; / [CORE] 6.1.0230 "slash" ( n1 n2 -- n3 )
;
; Divide n1 by n2, giving the single-cell quotient n3.  An ambiguous
; condition exists if n2 is zero.  If n1 and n2 differ in sign, the
; implementation-defined result returned will be the same as that returned
; by either the phrase >R S>D R> FM/MOD SWAP DROP or the phrase
; >R S>D R> SM/REM SWAP DROP.
;
; ---
; : / ( n1 n2 -- n3)   /MOD NIP ;

            .linkTo0 dotquote,0,1,'/'
slash JMP     enter
            .word   slashmod,nip,exit


; ----------------------------------------------------------------------
; /MOD [CORE] 6.1.0240 "slash-mod" ( n1 n2 -- n3 n4 )
;
; Divide n1 by n2, giving the single-cell remainder n3 and the single-cell
; quotient n4.  An ambiguous condition exists if n2 is zero.  If n1 and n2
; differ in sign, the implementation-defined result returned will be the
; same as that returned by either the phrase >R S>D R> FM/MOD or the phrase
; >R S>D R> SM/REM.
;
; ---
; : /MOD ( n1 n2 -- n3 n4)   >R S>D R> SM/REM ;

            .linkTo slash,0,4,'D',"OM/"
slashmod JMP     enter
            .word   tor,stod,rfrom,smslashrem,exit


; ----------------------------------------------------------------------
; 0< [CORE] 6.1.0250 "zero-less" ( b -- flag )
;
; flag is true if and only if n is less than zero.

            .linkTo slashmod,0,2,'<',"0"
zeroless POP     H           ; Pop the value.
            MOV     A,H         ; See if the number is < 0 by moving H to A
            ORA     A           ; ..and then ORing A with itself.
            JP      _zlessfalse ; Jump if positive to where we push false.
            LXI     H,0FFFFH    ; Put true in HL.
            JMP     _zlessdone  ; We're done.
_zlessfalse LXI     H,0         ; Put false in HL.
_zlessdone PUSH    H           ; Push the flag to the stack.
            .next


; ----------------------------------------------------------------------
; 0= [CORE] 6.1.0270 "zero-equals" ( x -- flag )
;
; flag is true if and only if x is equal to zero.

            .linkTo zeroless,0,2,'=',"0"
zeroequals POP     H           ; Pop the value.
            MOV     A,H         ; See if the flag is zero by moving H to A
            ORA     L           ; ..and then ORing A with L.
            JNZ     _zeqfalse   ; Jump if not zero to where we push false.
            LXI     H,0FFFFH    ; Put true in HL.
            JMP     _zeqdone    ; We're done.
_zeqfalse LXI     H,0         ; Put false in HL.
_zeqdone PUSH    H           ; Push the flag to the stack.
            .next


; ----------------------------------------------------------------------
; 1+ [CORE] 6.1.0290 "one-plus" ( n1|u1 -- n2|u2 )
;
; Add one (1) to n1|u1 giving the sum n2|u2.

            .linkTo zeroequals,0,2,'+',"1"
oneplus POP     H           ; Pop the value.
            INX     H           ; Increment the value.
            PUSH    H           ; Push the result onto the stack.
            .next


; ----------------------------------------------------------------------
; 1- [CORE] 6.1.0300 "one-minus" ( n1|u1 -- n2|u2 )
;
; Subtract one (1) from n1|u1 giving the difference n2|u2.

            .linkTo oneplus,0,2,'-',"1"
oneminus POP     H           ; Pop the value.
            DCX     H           ; Decrement the value.
            PUSH    H           ; Push the result onto the stack.
            .next


; ----------------------------------------------------------------------
; 2! [CORE] 6.1.0310 "two-store" ( x1 x2 a-addr -- )
;
; Store the cell pair x1 x2 at a-addr, with x2 at a-addr and x1 at the
; next consecutive cell.  It is equivalent to the sequence
; SWAP OVER ! CELL+ !.

            .linkTo oneminus,0,2,'!',"2"
twostore .saveDe
            POP     D           ; Pop a-addr.
            POP     H           ; Pop x2
            .byte 0D9H                ; Save x2.
            INX     D           ; Increment to the
            INX     D           ; ..next cell.
            POP     H           ; Pop x1.
            .byte 0D9H                ; Save x1.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; 2* [CORE] 6.1.0320 "two-star" ( x1 -- x2 )
;
; x2 is the result of shifting x1 one bit toward the most-significant bit,
; filling the vacated least-significant bit with zero.

            .linkTo twostore,0,2,'*',"2"
twostar POP     H           ; Pop x1.
            DAD     H           ; Double x1.
            PUSH    H           ; Push the result onto the stack.
            .next


; ----------------------------------------------------------------------
; 2/ [CORE] 6.1.0330 "two-slash" ( x1 -- x2 )
;
; x2 is the result of shifting x1 one bit toward the least-significant bit,
; leaving the most-significant bit unchanged.

            .linkTo twostar,0,2,'/',"2"
twoslash POP     H           ; Pop x1.
            ANA     A           ; Clear the carry flag.
            MOV     A,H         ; Move the high byte into A,
            RLC                 ; ..rotate it left
            RRC                 ; ..and then right through carry, then
            RAR                 ; ..divide the high byte,
            MOV     H,A         ; ..and put the high byte back into H.
            MOV     A,L         ; Move the low byte into A,
            RAR                 ; ..divide the low byte,
            MOV     L,A         ; ..and put the low byte back into H.
            PUSH    H           ; Push the result onto the stack.
            .next


; ----------------------------------------------------------------------
; 2@ [CORE] 6.1.0350 "two-fetch" ( a-addr -- x1 x2 )
;
; Fetch the cell pair x1 x2 stored at a-addr.  x2 is stored at a-addr
; and x1 at the next consecutive cell.  It is equivalent to the sequence
; DUP CELL+ @ SWAP @.

            .linkTo twoslash,0,2,'@',"2"
twofetch .saveDe
            POP     D           ; Pop a-addr.
_twofetchde .byte 0EDH                ; Fetch x2.
            PUSH    H           ; Push x2 (which is wrong, but we'll fix it).
            INX     D           ; Increment
            INX     D           ; ..to x1,
            .byte 0EDH                ; ..and fetch x1.
            XTHL                ; Swap TOS (x2) with x1.
            PUSH    H           ; Push x2.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; 2DROP [CORE] 6.1.0370 "two-drop" ( x1 x2 -- )
;
; Drop cell pair x1 x2 from the stack.

            .linkTo twofetch,0,5,'P',"ORD2"
twodrop POP     H
            POP     H
            .next


; ----------------------------------------------------------------------
; 2DUP [CORE] 6.1.0380 "two-dupe" ( x1 x2 -- x1 x2 x1 x2 )
;
; Duplicate cell pair x1 x2.

            .linkTo twodrop,0,4,'P',"UD2"
twodup .saveDe
            POP     H           ; Pop x2.
            POP     D           ; Pop x1.
            PUSH    D           ; Push x1 back onto the stack.
            PUSH    H           ; Push x2 back onto the stack.
            PUSH    D           ; Push another copy of x1 onto the stack.
            PUSH    H           ; Push another copy of x2 onto the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; 2OVER [CORE] 6.1.0400 "two-over" ( x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2 )
;
; Copy cell pair x1 x2 to the top of the stack.

            .linkTo twodup,0,5,'R',"EVO2"
twoover .saveDe
            .byte 038H,    6           ; Get the address of the fourth stack item.
            .byte 0EDH                ; Load the fourth stack item into HL.
            PUSH    H           ; Push the fourth stack item onto the stack.
            .byte 038H,    6           ; Get the address of the third (now fourth) stack item.
            .byte 0EDH                ; Load the third stack item into HL.
            PUSH    H           ; Push the third stack item onto the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; 2SWAP [CORE] 6.1.0430 "two-swap" ( x1 x2 x3 x4 -- x3 x4 x1 x2 )
;
; Exchange the top two cell pairs.

            .linkTo twoover,0,5,'P',"AWS2"
twoswap .saveDe
            POP     H           ; Pop x4.
            POP     D           ; Pop x3.
            XTHL                ; Swap x4 with x2.
            XCHG                ; Put x2 in DE, x3 in HL.
            DI                  ; Disable interrupts while we mess with SP.
            INX     SP          ; Increment SP
            INX     SP          ; ..to x1.
            XTHL                ; Swap x3 with x1.
            DCX     SP          ; Decrement back
            DCX     SP          ; ..to x4.
            EI                  ; Enable interrupts now that we're done with SP.
            XCHG                ; Put x1 in DE, x2 in HL.
            PUSH    D           ; Push x1.
            PUSH    H           ; Push x2.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; : [CORE] 6.1.0450 "colon" ( C: "<spaces>name" -- colon-sys )
;
; Skip leading space delimiters.  Parse name delimited by a space.  Create
; a definition for name, called a "colon definition".  Enter compilation
; state and start the current definition, producing colon-sys.  Append the
; initiation semantics given below to the current definition.
;
; The execution semantics of name will be determined by the words compiled
; into the body of the definition.  The current definition shall not be
; findable in the dictionary until it is ended (or until the execution of
; DOES> in some systems).
;
; Initiation: ( i*x -- i*x ) ( R: -- nest-sys )
;   Save implementation-dependent information nest-sys about the calling
;   definition.  The stack effects i*x represent arguments to name.
;
; name Execution: ( i*x -- j*x )
;       Execute the definition name.  The stack effects i*x and j*x
;       represent arguments to and results from name, respectively.

; ---
; : : ( "<spaces>name" -- )
;   CREATE HIDE ]  CFASZ NEGATE ALLOT  195 C, DOCOLON , ; -- JMP DOCOLON

            .linkTo0 twoswap,0,1,03AH
colon JMP     enter
            .word   create,hide,rtbracket
            .word   lit,-cfasz,allot,lit,195,ccomma,lit,docolon,comma
            .word   exit


; ----------------------------------------------------------------------
; ; [CORE] 6.1.0460 "semicolon"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: colon-sys -- )
;   Append the run-time semantics below to the current definition.  End
;   the current definition, allow it to be found in the dictionary and
;   enter interpretation state, consuming colon-sys.  If the data-space
;   pointer is not aligned, reserve enough data space to align it.
;
; Run-time: ( -- ) ( R: nest-sys -- )
;   Return to the calling definition specified by nest-sys.
;
; ---
; : ; ( -- )   REVEAL  ['] EXIT COMPILE,  POSTPONE [ ; IMMEDIATE

            .linkTo0 colon,1,1,';'
semicolon JMP     enter
            .word   reveal,lit,exit,compilecomma,ltbracket,exit


; ----------------------------------------------------------------------
; < [CORE] 6.1.0480 "less-than" ( n1 n2 -- flag )
;
; flag is true if and only if n1 is less than n2.

            .linkTo0 semicolon,0,1,'<'
lessthan .saveDe
            POP     D           ; Pop n2.
            POP     H           ; Pop n1.
            MOV     A,D         ; Put n2's high byte into A,
            XRA     H           ; ..XOR that with n1's high byte,
            JM      _lt1        ; ..then skip the DSUB if the signs differ.
            PUSH    B           ; Save BC.
            MOV     B,D         ; Move n2
            MOV     C,E         ; ..to BC.
            .byte 08H                ; HL=n1-n2
            POP     B           ; Restore BC.
_lt1 INR     H           ; Increment HL,
            DCR     H           ; ..then decrement HL to check the sign;
            JM      _lttrue     ; ..n1 < n2 if HL is negative.
            LXI     H,0         ; Put false in HL.
            JMP     _ltdone     ; We're done.
_lttrue LXI     H,0FFFFH    ; Put true in HL.
_ltdone PUSH    H           ; Push the flag to the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; <# [CORE] 6.1.0490 "less-number-sign" ( -- )
;
; Initialize the pictured numeric output conversion process.
;
; ---
; : <# ( -- )   HERE HLDEND + HLD ! ;

            .linkTo lessthan,0,2,'#',"<"
lessnumsign JMP     enter
            .word   here,lit,hldend,plus,hld,store
            .word   exit


; ----------------------------------------------------------------------
; = [CORE] 6.2.0530 "equals" ( x1 x2 -- flag )
;
; flag is true if and only if x1 is bit-for-bit the same as x2.

            .linkTo0 lessnumsign,0,1,'='
equals .saveDe
            POP     H           ; Pop x2.
            POP     D           ; Pop x1.
            PUSH    B           ; Save BC.
            MOV     B,D         ; Move x1
            MOV     C,E         ; ..to BC.
            .byte 08H                ; HL=HL-BC
            POP     B           ; Restore BC.
            JNZ     _eqfalse    ; Jump if not equals to where we push false.
            LXI     H,0FFFFH    ; Put true in HL.
            JMP     _eqdone     ; We're done.
_eqfalse LXI     H,0         ; Put false in HL.
_eqdone PUSH    H           ; Push the flag to the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; > [CORE] 6.1.0540 "greater-than" ( n1 n2 -- flag )
;
; flag is true if and only if n1 is greater than n2.
;
; ---
; : > ( n1 n2 -- flag)   SWAP < ;

            .linkTo0 equals,0,1,'>'
greaterthan JMP     enter
            .word   swap,lessthan,exit


; ----------------------------------------------------------------------
; >BODY [CORE] 6.1.0550 "to-body" ( xt -- a-addr )
;
; a-addr is the data-field address corresponding to xt.  An ambiguous
; condition exists if xt is not for a word defined via CREATE.
;
; ---
; : >BODY ( xt -- a-addr)   CFASZ + ;

            .linkTo greaterthan,0,5,'Y',"DOB>"
tobody JMP     enter
            .word   lit,cfasz,plus,exit


; ----------------------------------------------------------------------
; >IN [CORE] 6.1.0560 "to-in" ( -- a-addr )
;
; a-addr is the address of a cell containing the offset in characters
; from the start of the input buffer to the start of the parse area.
;
; ---
; : >IN ( -- a-addr)  ICB ICBTOIN + ;

            .linkTo tobody,0,3,'N',"I>"
toin JMP     enter
            .word   icb,lit,icbtoin,plus,exit


; ----------------------------------------------------------------------
; >NUMBER [CORE] 6.1.0567 "to-number" ( ud1 c-addr1 u1 -- ud2 c-addr2 u2 )
;
; ud2 is the unsigned result of converting the characters within the string
; specified by c-addr1 u1 into digits, using the number in BASE, and adding
; each into ud1 after multiplying ud1 by the number in BASE.  Conversion
; continues left-to-right until a character that is not convertible,
; including any "+" or "-", is encountered or the string is entirely
; converted.  c-addr2 is the location of the first unconverted character or
; the first character past the end of the string if the string was entirely
; converted.  u2 is the number of unconverted characters in the string.  An
; ambiguous condition exists if ud2 overflows during the conversion.
;
; ---
; : >NUMBER ( ud1 c-addr1 u1 -- ud2 c-addr2 u2)
;   2>B  BEGIN B? WHILE
;       B@ DIGIT? 0= IF B B# EXIT THEN
;       ( ud1 u) >R BASE @ UD* R> M+
;   B+ AGAIN  B B# ;

            .linkTo toin,0,7,'R',"EBMUN>"
tonumber JMP     enter
            .word   twotob
_tonumber1 .word   bques,zbranch,_tonumber3
            .word   bfetch,digitq,zeroequals,zbranch,_tonumber2
            .word   B,bnumber,exit
_tonumber2 .word   tor,base,fetch,udstar,rfrom,mplus,bplus,branch,_tonumber1
_tonumber3 .word   B,bnumber
            .word   exit


; ----------------------------------------------------------------------
; >R [CORE] 6.1.0580 "to-r"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( x -- ) ( R: -- x )
;   Move x to the return stack.

            .linkTo tonumber,0,2,'R',">"
tor POP     H
            .rsPush H,L
            .next


; ----------------------------------------------------------------------
; ?DUP [CORE] 6.1.0630 "question-dupe" ( x -- 0 | x x )
;
; Duplicate x if it is non-zero.

            .linkTo tor,0,4,'P',"UD?"
qdup POP     H           ; Pop x into HL.
            MOV     A,H         ; See if the value is zero by moving H to A
            ORA     L           ; ..and then ORing A with L.
            JZ      _qduponce   ; Jump if zero to where we push once.
            PUSH    H           ; Push the value (this is the second copy).
_qduponce PUSH    H           ; Push the value.
            .next


; ----------------------------------------------------------------------
; @ [CORE] 6.1.0650 "fetch" ( a-addr -- x )
;
; x is the value stored at a-addr.

            .linkTo0 qdup,0,1,'@'
fetch POP     H           ; Pop address to fetch into HL
            MOV     A,M         ; Load LSB of cell value into A
            INX     H           ; Increment to MSB of the cell value
            MOV     H,M         ; Load MSB of the cell value into H
            MOV     L,A         ; Move LSB of cell value from A to L
            PUSH    H           ; Push cell value onto stack.
            .next


; ----------------------------------------------------------------------
; ABORT [CORE] 6.1.0670 ( i*x -- ) ( R: j*x -- )
;
; Empty the data stack and perform the function of QUIT, which includes
; emptying the return stack, without displaying a message.
;
; ---
; : ABORT ( i*x -- ) ( R: j*x -- )
;   TASK-PAGE [HEX] FF OR SP!  10 BASE !
;   TASK-PAGE 'FIRSTTASK @ = IF ONLY QUIT ELSE ['] BL STOPPED THEN ;
;
; Our multitasking-aware version of ABORT enters the QUIT loop if this
; is the initial task, otherwise the STOPPED loop is invoked and the
; task effectively becomes inert.  STOPPED needs an xt to call, so we
; give it BL.  That puts a value on the stack, but since STOPPED will
; never exit the value won't bother anyone.
;
; Note that ABORT will also (re-)initialize the search order if it is
; called from the initial task.
;
; The idle word should never return, but we HALT anyway just in case
; someone messes with the return stack.

            .linkTo fetch,0,5,'T',"ROBA"
abort JMP     enter
            .word   taskpage,lit,0FFH,or,spstore
            .word   lit,10,base,store
            .word   taskpage,lit,tickfirsttask,fetch,equals,zbranch,_abort1
            .word   only,quit,halt
_abort1 .word   lit,bl,stopped,halt


; ----------------------------------------------------------------------
; ABORT" [CORE] 6.1.0680 "abort-quote"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( "ccc<quote>" -- )
;   Parse ccc delimited by a " (double-quote).  Append the run-time
;   semantics given below to the current definition.
;
; Run-time: ( i*x x1 --  | i*x ) ( R: j*x --  | j*x )
;   Remove x1 from the stack.  If any bit of x1 is not zero, display ccc
;   and perform an implementation-defined abort sequence that includes the
;   function of ABORT.
;
; ---
; : ABORT"   POSTPONE IF POSTPONE ." POSTPONE ABORT THEN ; IMMEDIATE

            .linkTo abort,1,6,022H,"TROBA"
abortquote JMP     enter
            .word   if,dotquote,lit,abort,compilecomma,then,exit


; ----------------------------------------------------------------------
; ABS [CORE] 6.1.0690 "abs" ( n -- u )
;
; u is the absolute value of n.
;
; ---
; : ABS ( n -- u )   DUP ?NEGATE ;

            .linkTo abortquote,0,3,'S',"BA"
abs JMP     enter
            .word   dup,qnegate,exit


; ----------------------------------------------------------------------
; ACCEPT [CORE] 6.1.0695 ( c-addr +n1 -- +n2 )
;
; Receive a string of at most +n1 characters.  An ambiguous condition
; exists if +n1 is zero or greater than 32,767.  Display graphic
; characters as they are received.  A program that depends on the
; presence or absence of non-graphic characters in the string has an
; environmental dependency.  The editing functions, if any, that the
; system performs in order to construct the string are
; implementation-defined.
;
; Input terminates when an implementation-defined line terminator is
; received.  When input terminates, nothing is appended to the string,
; and the display is maintained in an implementation-defined way.
;
; +n2 is the length of the string stored at c-addr.
;
; ---
; : ACCEPT ( c-addr max -- n)
;   2DUP 2>B DROP  ( ca-start)
;   BEGIN  KEY  DUP 13 <> WHILE
;       DUP 8 = IF
;           ( ca-start bs) DROP  B OVER - IF 8 EMIT BL EMIT 8 EMIT -1 'B +! THEN
;       ELSE
;           B? IF DUP EMIT B!+ ELSE DROP THEN
;       THEN
;   REPEAT
;   ( ca-start cr) DROP  B SWAP - ;

            .linkTo abs,0,6,'T',"PECCA"
accept JMP     enter
            .word   twodup,twotob,drop
_accept1 .word   key,dup,lit,13,notequals,zbranch,_accept5
            .word   dup,lit,8,equals,zbranch,_accept2
            .word   drop,B,over,minus,zbranch,_accept4
            .word   lit,8,emit,bl,emit,lit,8,emit
            .word       lit,-1,tickb,plusstore,branch,_accept4
_accept2 .word   bques,zbranch,_accept3,dup,emit,bstoreplus,branch,_accept4
_accept3 .word   drop
_accept4 .word   branch,_accept1
_accept5 .word   drop,B,swap,minus
            .word   exit


; ----------------------------------------------------------------------
; ALIGN [CORE] 6.1.0705 ( -- )
;
; If the data-space pointer is not aligned, reserve enough space to align it.

            .linkTo accept,0,5,'N',"GILA"
align .next                ; No-op in MFORTH; no alignment needed.


; ----------------------------------------------------------------------
; ALIGNED [CORE] 6.1.0706 ( addr -- a-addr )
;
; a-addr is the first aligned address greater than or equal to addr.

            .linkTo align,0,7,'D',"ENGILA"
aligned .next                ; No-op in MFORTH; no alignment needed.


; ----------------------------------------------------------------------
; ALLOT [CORE] 6.1.0710 ( n -- )
;
; If n is greater than zero, reserve n address units of data space.  If
; n is less than zero, release |n| address units of data space.  If n is
; zero, leave the data-space pointer unchanged.
;
; If the data-space pointer is aligned and n is a multiple of the size of
; a cell when ALLOT begins execution, it will remain aligned when ALLOT
; finishes execution.
;
; If the data-space pointer is character aligned and n is a multiple of
; the size of a character when ALLOT begins execution, it will remain
; character aligned when ALLOT finishes execution.
;
; ---
; : ALLOT ( n -- )   DP +! ;

            .linkTo aligned,0,5,'T',"OLLA"
allot JMP     enter
            .word   lit,dp,plusstore,exit


; ----------------------------------------------------------------------
; AND [CORE] 6.1.0720 ( x1 x2 -- x3 )
;
; x3 is the bit-by-bit logical "and" of x1 with x2.

            .linkTo allot,0,3,'D',"NA"
and .saveDe
            POP     H           ; Pop x2.
            POP     D           ; Pop x1.
            MOV     A,H         ; Put x2's high byte into A,
            ANA     D           ; ..then AND x1's high byte with A,
            MOV     H,A         ; ..and put the result into H.
            MOV     A,L         ; Put x2's low byte into A,
            ANA     E           ; ..then AND x1's low byte with A,
            MOV     L,A         ; ..and put the result into L.
            PUSH    H           ; Push the result (HL).
            .restoreDe
            .next


; ----------------------------------------------------------------------
; BASE [CORE] 6.1.0750 ( -- a-addr )
;
; a-addr is the address of a cell containing the current number-conversion
; radix {{2...36}}.

            .linkTo and,0,4,'E',"SAB"
base JMP     douser
            .byte   userbase


; ----------------------------------------------------------------------
; BEGIN [CORE] 6.1.0760
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: -- dest )
;   Put the next location for a transfer of control, dest, onto the control
;   flow stack.  Append the run-time semantics given below to the current
;   definition.
;
; Run-time: ( -- )
;   Continue execution.
;
; ---
; : BEGIN   HERE ; IMMEDIATE

            .linkTo base,1,5,'N',"IGEB"
begin JMP     enter
            .word   here,exit


; ----------------------------------------------------------------------
; BL [CORE] 6.1.0770 "b-l" ( -- char )
;
; char is the character value for a space.

            .linkTo begin,0,2,'L',"B"
bl LXI     H,020H
            PUSH    H
            .next


; ----------------------------------------------------------------------
; C! [CORE] 6.1.0850 "c-store" ( char c-addr -- )
;
; Store char at c-addr.  When character size is smaller than cell size,
; only the number of low-order bits corresponding to character size are
; transferred.

            .linkTo bl,0,2,'!',"C"
cstore .saveDe
            POP     H           ; Pop c-addr.
            POP     D           ; Pop char
            MOV     M,E         ; Store LSB of char value.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; C, [CORE] 6.1.0860 "c-comma" ( char -- )
;
; Reserve space for one character in the data space and store char in the
; space.  If the data-space pointer is character aligned when C, begins
; execution, it will remain character aligned when C, finishes execution.
; An ambiguous condition exists if the data-space pointer is not
; character-aligned prior to execution of C,.
;
; ---
; : C, ( char -- )   HERE C!  1 CHARS ALLOT ;

            .linkTo cstore,0,2,02CH,"C"
ccomma JMP     enter
            .word   here,cstore,one,chars,allot,exit


; ----------------------------------------------------------------------
; C@ [CORE] 6.1.0870 "c-fetch" ( c-addr -- char )
;
; Fetch the character stored at c-addr.  When the cell size is greater
; than character size, the unused high-order bits are all zeroes.

            .linkTo ccomma,0,2,'@',"C"
cfetch POP     H           ; Pop address to fetch into HL.
            MOV     L,M         ; Load character into low byte of HL.
            MVI     H,0         ; Clear high byte of HL.
            PUSH    H           ; Push character value onto stack.
            .next


; ----------------------------------------------------------------------
; CELL+ [CORE] 6.1.0880 "cell-plus" ( a-addr1 -- a-addr2 )
;
; Add the size in address units of a cell to a-addr1, giving a-addr2.

            .linkTo cfetch,0,5,'+',"LLEC"
cellplus POP     H           ; Pop a-addr1.
            INX     H           ; Add two (the size of a cell)
            INX     H           ; ..to a-addr1.
            PUSH    H           ; Push the result to the stack.
            .next


; ----------------------------------------------------------------------
; CELLS [CORE] 6.1.0890 ( n1 -- n2 )
;
; n2 is the size in address units of n1 cells.

            .linkTo cellplus,0,5,'S',"LLEC"
cells POP     H           ; Pop x1.
            DAD     H           ; Double x1 (cells are two bytes wide).
            PUSH    H           ; Push the result onto the stack.
            .next


; ----------------------------------------------------------------------
; CHAR [CORE] 6.1.0895 "char" ( "<spaces>name" -- char )
;
; Skip leading space delimiters.  Parse name delimited by a space.  Put
; the value of its first character onto the stack.
;
; ---
; : CHAR ( "<spaces>name" -- char)   PARSE-WORD DROP C@ ;

            .linkTo cells,0,4,'R',"AHC"
char JMP     enter
            .word   parseword,drop,cfetch,exit


; ----------------------------------------------------------------------
; CHAR+ [CORE] 6.1.0897 "char-plus" ( c-addr1 -- c-addr2 )
;
; Add the size in address units of a character to c-addr1, giving c-addr2.

            .linkTo char,0,5,'+',"RAHC"
charplus POP     H           ; Pop c-addr1.
            INX     H           ; Add one (the size of a char) to c-addr1.
            PUSH    H           ; Push the result to the stack.
            .next


; ----------------------------------------------------------------------
; CHARS [CORE] 6.1.0898 "chars" ( n1 -- n2 )
;
; n2 is the size in address units of n1 characters.

            .linkTo charplus,0,5,'S',"RAHC"
chars .next                ; No-op in MFORTH, because chars are 1 byte.


; ----------------------------------------------------------------------
; CONSTANT [CORE] 6.1.0950 ( x "<spaces>name" -- )
;
; Skip leading space delimiters.  Parse name delimited by a space.  Create
; a definition for name with the execution semantics defined below.
;
; name is referred to as a "constant".
;
; name Execution: ( -- x )
;   Place x on the stack.
;
; ---
; : CONSTANT ( x "<spaces>name" -- )
;   CREATE  CFASZ NEGATE ALLOT  195 C, DOCONSTANT ,  , ; -- JMP DOCONSTANT

            .linkTo chars,0,8,'T',"NATSNOC"
constant JMP     enter
            .word   create,lit,-cfasz,allot,lit,195,ccomma,lit,doconstant,comma
            .word   comma,exit


; ----------------------------------------------------------------------
; COUNT [CORE] 6.1.0980 ( c-addr1 -- c-addr2 u )
;
; Return the character string specification for the counted string stored
; at c-addr1.  c-addr2 is the address of the first character after c-addr1.
; u is the contents of the character at c-addr1, which is the length in
; characters of the string at c-addr2.

            .linkTo constant,0,5,'T',"NUOC"
count POP     H           ; Pop the address into HL.
            MOV     A,M         ; Fetch the string count into A.
            INX     H           ; Increment HL to the address of the string.
            PUSH    H           ; Push the address of the string to the stack.
            MVI     H,0         ; Clear the high byte of HL,
            MOV     L,A         ; ..set the low byte to the count,
            PUSH    H           ; ..and push the count to the stack.
            .next


; ----------------------------------------------------------------------
; CR [CORE] 6.1.0990 "c-r" ( -- )
;
; Cause subsequent output to appear at the beginning of the next line.

            .linkTo count,0,2,'R',"C"
cr CALL    stdcall     ; Call the
            .word   04222H      ; .."Send CRLF" routine.
            .next


; ----------------------------------------------------------------------
; CREATE [CORE] 6.1.1000 ( "<spaces>name" -- )
;
; Skip leading space delimiters.  Parse name delimited by a space.  Create
; a definition for name with the execution semantics defined below.  If
; the data-space pointer is not aligned, reserve enough data space to
; align it.  The new data-space pointer defines name's data field.  CREATE
; does not allocate data space in name's data field.
;
;   name Execution: ( -- a-addr )
;       a-addr is the address of name's data field.  The execution
;       semantics of name may be extended by using DOES>.
;
; ---
; : CREATE ( "<spaces>name" -- )
;   PARSE-WORD  DUP 0= IF ABORT THEN DUP 63 > IF ABORT THEN
;   2>B  B# 1+ ALLOT  HERE 1-  B# OVER C!
;   FORB 1- B@ OVER C! NEXTB  DUP C@ 128 OR SWAP C!
;   LATEST @ ,  [ PROFILER ] [IF] 0 , [THEN]
;   HERE NFATOCFASZ - LATEST !  195 C, DOCREATE , -- JMP DOCREATE
;

            .linkTo cr,0,6,'E',"TAERC"
create JMP     enter
            .word   parseword,dup,zeroequals,zbranch,_create1,abort
_create1 .word   dup,lit,63,greaterthan,zbranch,_create2,abort
_create2 .word   twotob,bnumber,oneplus,allot,here,oneminus
            .word       bnumber,over,cstore
_create3 .word   bques,zbranch,_create4,oneminus,bfetch,over,cstore
            .word       bplus,branch,_create3
_create4 .word   dup,cfetch,lit,128,or,swap,cstore
            .word   latest,fetch,comma
.ifdef profiler
            .word   zero,comma
.endif
            .word   here,lit,nfatocfasz,minus,latest,store
            .word       lit,195,ccomma,lit,docreate,comma
            .word   exit


; ----------------------------------------------------------------------
; DECIMAL [CORE] 6.1.1170 ( -- )
;
; Set the numeric conversion radix to ten (decimal).

            .linkTo create,0,7,'L',"AMICED"
decimal JMP     enter
            .word   lit,10,base,store,exit


; ----------------------------------------------------------------------
; DEPTH [CORE] 6.1.1200 ( -- +n )
;
; +n is the number of single-cell values contained in the data stack
; before +n was placed on the stack.
;
; ---
; : DEPTH ( -- +n)   SP  TASK-PAGE [HEX] FF OR  SWAP - 2/ ;

            .linkTo decimal,0,5,'H',"TPED"
depth JMP     enter
            .word   SP,taskpage,lit,0FFH,or,swap,minus,twoslash,exit


; ----------------------------------------------------------------------
; DO [CORE] 6.1.1240
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: -- do-sys )
;   Place do-sys onto the control-flow stack.  Append the run-time
;   semantics given below to the current definition.  The semantics are
;   incomplete until resolved by a consumer of do-sys such as LOOP.
;
; Run-time: ( n1|u1 n2|u2 -- ) ( R: -- loop-sys )
;   Set up loop control parameters with index n2|u2 and limit n1|u1. An
;   ambiguous condition exists if n1|u1 and n2|u2 are not both the same
;   type.  Anything already on the return stack becomes unavailable until
;   the loop-control parameters are discarded.
;
; ---
; do-sys in MFORTH is ( do-orig ).  LEAVE locations chain from the most
; recent LEAVE to the oldest LEAVE and then to zero, which signifies the
; end of the LEAVE list.  LOOP/+LOOP go through the LEAVE list and fix
; up the addresses.
;
; : DO   0 'PREVLEAVE !  ['] (do) COMPILE,  HERE ; IMMEDIATE

            .linkTo depth,1,2,'O',"D"
do JMP     enter
            .word   zero,lit,tickprevleave,store,lit,pdo,compilecomma,here,exit


; ----------------------------------------------------------------------
; DOES> [CORE] 6.1.1250
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: colon-sys1 -- colon-sys2 )
;   Append the run-time semantics below to the current definition.  Whether
;   or not the current definition is rendered findable in the dictionary by
;   the compilation of DOES> is implementation defined.  Consume colon-sys1
;   and produce colon-sys2.  Append the initiation semantics given below to
;   the current definition.
;
; Run-time: ( -- ) ( R: nest-sys1 -- )
;   Replace the execution semantics of the most recent definition, referred
;   to as name, with the name execution semantics given below.  Return
;   control to the calling definition specified by nest-sys1.  An ambiguous
;   condition exists if name was not defined with CREATE or a user-defined
;   word that calls CREATE.
;
; Initiation: ( i*x -- i*x a-addr ) ( R: -- nest-sys2 )
;   Save implementation-dependent information nest-sys2 about the calling
;   definition.  Place name's data field address on the stack.  The stack
;   effects i*x represent arguments to name.
;
; name Execution: ( i*x -- j*x )
;   Execute the portion of the definition that begins with the initiation
;   semantics appended by the DOES> which modified name.  The stack effects
;   i*x and j*x represent arguments to and results from name, respectively.
;
; ---
; : (does>)
;   R>                  -- Get the new CFA for this def'n, which also exits
;                       -- the current def'n since we just popped the defining
;                       -- word's address from the return stack.
;   LATEST @ NFA>CFA    -- Get address of LATEST's CFA.
;   195 OVER C!  1+ !   -- Replace CFA with a JMP (195) to the code after DOES>
;                       -- which in our implementation is CALL DODOES and then
;                       -- the high-level thread after DOES>.
; ;
;
; : DOES> ( -- )
;   ['] (does>) COMPILE,  205 C, DODOES , -- CALL DODOES
; ; IMMEDIATE

            .linkTo do,1,5,'>',"SEOD"
does JMP     enter
            .word   lit,pdoes,compilecomma,lit,205,ccomma,lit,dodoes,comma,exit
pdoes JMP     enter
            .word   rfrom,latest,fetch,nfatocfa
            .word   lit,195,over,cstore,oneplus,store,exit


; ----------------------------------------------------------------------
; DROP [CORE] 6.1.1260  ( x -- )
;
; Remove x from the stack.

            .linkTo does,0,4,'P',"ORD"
drop POP     H
            .next


; ----------------------------------------------------------------------
; DUP [CORE] 6.1.1290 "dupe" ( x -- x x )
;
; Duplicate x.

            .linkTo drop,0,3,'P',"UD"
dup POP     H
            PUSH    H
            PUSH    H
            .next


; ----------------------------------------------------------------------
; ELSE [CORE] 6.1.1310
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: orig1 -- orig2 )
;   Put the location of a new unresolved forward reference orig2 onto the
;   control flow stack.  Append the run-time semantics given below to the
;   current definition.  The semantics will be incomplete until orig2 is
;   resolved (e.g., by THEN).  Resolve the forward reference orig1 using
;   the location following the appended  run-time semantics.
;
; Run-time: ( -- )
;   Continue execution at the location given by the resolution of orig2.
;
; ---
; : ELSE   ['] branch COMPILE,  HERE DUP ,  SWAP POSTPONE THEN ; IMMEDIATE

            .linkTo dup,1,4,'E',"SLE"
else JMP     enter
            .word   lit,branch,compilecomma,here,dup,comma,swap,then,exit


; ----------------------------------------------------------------------
; EMIT [CORE] 6.1.1320 ( x -- )
;
; If x is a graphic character in the implementation-defined character set,
; display x.  The effect of EMIT for all other values of x is
; implementation-defined.
;
; When passed a character whose character-defining bits have a value between
; hex 20 and 7E inclusive, the corresponding standard character, specified by
; 3.1.2.1 Graphic characters, is displayed.  Because different output devices 
; can respond differently to control characters, programs that use control
; characters to perform specific functions have an environmental dependency.
; Each EMIT deals with only one character.

            .linkTo else,0,4,'T',"IME"
emit POP     H           ; Pop the character into HL
            MOV     A,L         ; ..and then move it into A.
            CALL    stdcall     ; Call the
            .word   04B44H      ; .."character output" routine.
            .next


; ----------------------------------------------------------------------
; ENVIRONMENT? [CORE] 6.1.1345 "environment-query" ( c-addr u -- false | i*x true )
;
; c-addr is the address of a character string and u is the string's character
; count.  u may have a value in the range from zero to an implementation-defined
; maximum which shall not be less than 31.  The character string should contain
; a keyword from 3.2.6 Environmental queries or the optional word sets to be
; checked for correspondence with an attribute of the present environment.  If
; the system treats the attribute as unknown, the returned flag is false;
; otherwise, the flag is true and the i*x returned is of the type specified in
; the table for the attribute queried.
;
; TODO: Implement ENVIRONMENT?


; ----------------------------------------------------------------------
; EVALUATE [CORE] 6.2.1360 ( i*x c-addr u -- j*x )
;
; Save the current input source specification.  Store minus-one (-1) in
; SOURCE-ID if it is present.  Make the string described by c-addr and u
; both the input source and input buffer, set >IN to zero, and interpret.
; When the parse area is empty, restore the prior input source specification.
; Other stack effects are due to the words EVALUATEd.
;
; ---
; : EVALUATE ( i*x c-addr u -- j*x)
;   PUSHICB  OVER + ICB 2!  -1 ICB ICBSOURCEID + !  INTERPRET  POPICB ;

            .linkTo emit,0,8,'E',"TAULAVE"
evaluate JMP     enter
            .word   pushicb,over,plus,icb,twostore
            .word   lit,-1,icb,lit,icbsourceid,plus,store
            .word   interpret,popicb,exit


; ----------------------------------------------------------------------
; EXECUTE [CORE] 6.1.1370 ( i*x xt -- j*x )
;
; Remove xt from the stack and perform the semantics identified by it.
; Other stack effects are due to the word EXECUTEd.

            .linkTo evaluate,0,7,'E',"TUCEXE"
execute POP     H           ; Pop xt.
            PCHL                ; Execute xt.


; ----------------------------------------------------------------------
; EXIT [CORE] 6.1.1380
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( -- ) ( R: nest-sys -- )
;   Return control to the calling definition specified by nest-sys.  Before
;   executing EXIT within a do-loop, a program shall discard the loop-control
;   parameters by executing UNLOOP.

            .linkTo execute,0,4,'T',"IXE"
exit .rsPop D,E
            .next


; ----------------------------------------------------------------------
; FILL [CORE] 6.1.1540 ( c-addr u char -- )
;
; If u is greater than zero, store char in each of u consecutive
; characters of memory beginning at c-addr.
;
; ---
; : FILL ( c-addr u char --)   ROT ROT 2>B FORB DUP B! NEXTB DROP ;

            .linkTo exit,0,4,'L',"LIF"
fill JMP     enter
            .word   rot,rot,twotob
_fill1 .word   bques,zbranch,_fill2
            .word   dup,bstore,bplus,branch,_fill1
_fill2 .word   drop,exit


; ----------------------------------------------------------------------
; FIND [CORE] 6.1.1550 ( c-addr -- c-addr 0 | xt 1 | xt -1 )
;
; Find the definition named in the counted string at c-addr.  If the
; definition is not found after searching all the word lists in the
; search order, return c-addr and zero.  If the definition is found,
; return xt.  If the definition is immediate, also return one (1);
; otherwise also return minus-one (-1).  For a given string, the values
; returned by FIND while compiling may differ from those returned while
; not compiling.
;
; ---
; : FIND ( c-addr -- c-addr 0 | xt 1 | xt -1 )
;   COUNT (FIND) ?DUP 0= IF DROP 1- 0 THEN ;

            .linkTo fill,0,4,'D',"NIF"
find JMP     enter
            .word   count,pfind,qdup,zeroequals,zbranch,_find1
            .word   drop,oneminus,zero
_find1 .word   exit


; ----------------------------------------------------------------------
; FM/MOD [CORE] 6.1.1561 "f-m-slash-mod" ( d1 n1 -- n2 n3 )
;
; Divide d1 by n1, giving the floored quotient n3 and the remainder n2.
; Input and output stack arguments are signed.  An ambiguous condition
; exists if n1 is zero or if the quotient lies outside the range of a
; single-cell signed integer. 
;
; ---
; Floored division is integer division in which the remainder carries the
; sign of the divisor or is zero, and the quotient is rounded to its
; arithmetic floor.
;
; ---
; : FM/MOD ( d1 n1 -- n2 n3)
;   DUP >R ( num den R:signrem) 2DUP XOR ( num den signquo R:signrem)
;   SWAP ABS DUP >R ( num signquo +den R:signrem +den)
;   SWAP >R >R DABS R> ( num +den R:signrem +den signquo) SM/REM ( rem quo R:..)
;   R> 0< IF NEGATE OVER 0<> IF 1- SWAP R> SWAP - SWAP ELSE R> DROP THEN
;       ELSE R> DROP THEN
;   R> 0< IF SWAP NEGATE SWAP THEN ;

            .linkTo find,0,6,'D',"OM/MF"
fmslashmod JMP     enter
            .word   dup,tor,twodup,xor,swap,abs,dup,tor
            .word   swap,tor,tor,dabs,rfrom,umslashmod
            .word   rfrom,zeroless,zbranch,_fmslashmod1
            .word   negate,over,zeronotequals,zbranch,_fmslashmod1
            .word   oneminus,swap,rfrom,swap,minus,swap,branch,_fmslashmod2
_fmslashmod1 .word  rfrom,drop
_fmslashmod2 .word  rfrom,zeroless,zbranch,_fmslashmod3
            .word   swap,negate,swap
_fmslashmod3 .word  exit


; ----------------------------------------------------------------------
; HERE [CORE] 6.1.1650 ( -- addr )
;
; addr is the data-space pointer.

            .linkTo fmslashmod,0,4,'E',"REH"
here LHLD    dp
            PUSH    H
            .next


; ----------------------------------------------------------------------
; HOLD [CORE] 6.1.1670 ( char -- )
;
; Add char to the beginning of the pictured numeric output string.  An
; ambiguous condition exists if HOLD executes outside of a <# #> delimited
; number conversion.
;
; ---
; : HOLD ( c -- )   HLD @ 1- DUP HLD ! C! ;

            .linkTo here,0,4,'D',"LOH"
hold JMP     enter
            .word   hld,fetch,oneminus,dup,hld,store,cstore
            .word   exit


; ----------------------------------------------------------------------
; I [CORE] 6.1.1680
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( -- n|u ) ( R:  loop-sys -- loop-sys )
;   n|u is a copy of the current (innermost) loop index.  An ambiguous
;   condition exists if the loop control parameters are unavailable.

            .linkTo0 hold,0,1,'I'
i .rsFetch H,L        ; Get the loop index into HL
            PUSH    H           ; ..and push it onto the stack.
            .next


; ----------------------------------------------------------------------
; IF [CORE] 6.1.1700
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: -- orig )
;   Put the location of a new unresolved forward reference orig onto the
;   control flow stack. Append the run-time semantics given below to the
;   current definition.  The semantics are incomplete until orig is resolved,
;   e.g., by THEN or ELSE.
;
; Run-time: ( x -- )
;   If all bits of x are zero, continue execution at the location specified
;   by the resolution of orig.
;
; ---
; : IF   ['] 0branch COMPILE,  HERE DUP , ; IMMEDIATE

            .linkTo i,1,2,'F',"I"
if JMP     enter
            .word   lit,zbranch,compilecomma,here,dup,comma,exit


; ----------------------------------------------------------------------
; IMMEDIATE [CORE] 6.1.1710 ( -- )
;
; Make the most recent definition an immediate word.  An ambiguous
; condition exists if the most recent definition does not have a name.
;
; ---
; : IMMEDIATE ( -- )   LATEST @  DUP C@ [HEX] 80 OR  SWAP C! ;

            .linkTo if,0,9,'E',"TAIDEMMI"
immediate JMP     enter
            .word   latest,fetch,dup,cfetch,lit,080H,or,swap,cstore,exit


; ----------------------------------------------------------------------
; INVERT [CORE] 6.1.1720 ( x1 -- x2 )
;
; Invert all bits of x1, giving its logical inverse x2.

            .linkTo immediate,0,6,'T',"REVNI"
invert POP     H           ; Pop x1.
            MOV     A,H         ; Put x1's high byte into A,
            CMA                 ; ..then complement x1's high byte,
            MOV     H,A         ; ..and put the result back into H.
            MOV     A,L         ; Put x1's low byte into A,
            CMA                 ; ..then complement x1's low byte,
            MOV     L,A         ; ..and put the result back into L.
            PUSH    H           ; Push the result (HL).
            .next


; ----------------------------------------------------------------------
; J [CORE] 6.1.1730
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( -- n|u ) ( R: loop-sys1 loop-sys2 -- loop-sys1 loop-sys2 )
;   n|u is a copy of the next-outer loop index.  An ambiguous condition
;   exists if the loop control parameters of the next-outer loop, loop-sys1,
;   are unavailable.

            .linkTo0 invert,0,1,'J'
j .rsPick2 H,L        ; Get the second loop index (the 3rd RS item)
            PUSH    H           ; ..into HL and push it onto the stack.
            .next


; ----------------------------------------------------------------------
; KEY [CORE] 6.1.1750 ( -- char )
;
; Receive one character char, a member of the implementation-defined
; character set.  Keyboard events that do not correspond to such characters
; are discarded until a valid character is received, and those events are
; subsequently unavailable.
;
; All standard characters can be received.  Characters received by KEY are
; not displayed.
;
; Any standard character returned by KEY has the numeric value specified in
; 3.1.2.1 Graphic characters.  Programs that require the ability to receive
; control characters have an environmental dependency.
;
; ---
; NOTE: Wake up from power off generates a null key event, which we need
; to ignore.
;
; : KEY ( -- char)   BEGIN  BEGIN PAUSE KEY? UNTIL  (KEY) ?DUP 0<> UNTIL ;

            .linkTo j,0,3,'Y',"EK"
key JMP     enter
_key1 .word   pause,keyq,zbranch,_key1
            .word   pkey,qdup,zeronotequals,zbranch,_key1
            .word   exit


; ----------------------------------------------------------------------
; LEAVE [CORE] 6.1.1760
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( -- ) ( R: loop-sys -- )
;   Discard the current loop control parameters.  An ambiguous condition
;   exists if they are unavailable.  Continue execution immediately
;   following the innermost syntactically enclosing DO ... LOOP or
;   DO ... +LOOP.
;
; ---
; LEAVE ( do-orig)
;   ['] UNLOOP COMPILE,  ['] branch COMPILE,
;   HERE  'PREVLEAVE @ ,  'PREVLEAVE !
; ; IMMEDIATE

            .linkTo key,1,5,'E',"VAEL"
leave JMP     enter
            .word   lit,unloop,compilecomma,lit,branch,compilecomma
            .word   here,lit,tickprevleave,fetch,comma
            .word   lit,tickprevleave,store,exit


; ----------------------------------------------------------------------
; LITERAL [CORE] 6.1.1780
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( x -- )
;   Append the run-time semantics given below to the current definition.
;
; Run-time: ( -- x )
;   Place x on the stack.
;
; ---
; : LITERAL ( x -- )   ['] LIT COMPILE,  ,  ; IMMEDIATE

            .linkTo leave,1,7,'L',"ARETIL"
literal JMP     enter
            .word   lit,lit,compilecomma,comma,exit


; ----------------------------------------------------------------------
; LOOP [CORE] 6.1.1800
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: do-sys -- )
;   Append the run-time semantics given below to the current definition.
;   Resolve the destination of all unresolved occurrences of LEAVE between
;   the location given by do-sys and the next location for a transfer of
;   control, to execute the words following the LOOP.
;
; Run-time: ( -- ) ( R: loop-sys1 -- | loop-sys2 )
;   An ambiguous condition exists if the loop control parameters are
;   unavailable.  Add one to the loop index.  If the loop index is then
;   equal to the loop limit, discard the loop parameters and continue
;   execution immediately following the loop.  Otherwise continue execution
;   at the beginning of the loop.
;
; ---
; : LOOP   ['] (loop) END-LOOP ; IMMEDIATE

            .linkTo literal,1,4,'P',"OOL"
loop JMP     enter
            .word   lit,ploop,endloop,exit


; ----------------------------------------------------------------------
; LSHIFT [CORE] 6.1.1805 "l-shift" ( x1 u -- x2 )
;
; Perform a logical left shift of u bit-places on x1, giving x2.  Put
; zeroes into the least significant bits vacated by the shift.  An
; ambiguous condition exists if u is greater than or equal to the number
; of bits in a cell.

            .linkTo loop,0,6,'T',"FIHSL"
lshift POP     H           ; Pop u into HL,
            MOV     A,L         ; ..then move the low byte into H.
            POP     H           ; Pop x1 into HL.
_lshift1 ANA     A           ; See if the count is zero;
            JZ      _lshiftdone ; ..we're done if so.
            DAD     H           ; Left-shift HL by adding HL to itself.
            DCR     A           ; Decrement the counter
            JMP     _lshift1    ; ..and continue looping.
_lshiftdone PUSH    H           ; Push the result (HL).
            .next


; ----------------------------------------------------------------------
; M* [CORE] 6.1.1810 "m-star" ( n1 n2 -- d )
;
; d is the signed product of n1 times n2.
;
; ---
; : M* ( n1 n2 -- d )   2DUP XOR 0< >R  ABS SWAP ABS UM*  R> ?DNEGATE ;

            .linkTo lshift,0,2,'*',"M"
mstar JMP     enter
            .word   twodup,xor,zeroless,tor,abs,swap,abs,umstar
            .word   rfrom,qdnegate,exit


; ----------------------------------------------------------------------
; MAX [CORE] 6.1.1870 ( n1 n2 -- n3 )
;
; n3 is the greater of n1 and n2.
;
; ---
; : MAX ( n1 n2 -- n3 )   2DUP < IF SWAP THEN DROP ;

            .linkTo mstar,0,3,'X',"AM"
max JMP     enter
            .word   twodup,lessthan,zbranch,_maxdone,swap
_maxdone .word   drop,exit


; ----------------------------------------------------------------------
; MIN [CORE] 6.1.1880 ( n1 n2 -- n3 )
;
; n3 is the lesser of n1 and n2.
;
; ---
; : MIN ( n1 n2 -- n3 )   2DUP > IF SWAP THEN DROP ;

            .linkTo max,0,3,'N',"IM"
min JMP     enter
            .word   twodup,greaterthan,zbranch,_mindone,swap
_mindone .word   drop,exit


; ----------------------------------------------------------------------
; MOD [CORE] 6.1.1890 ( n1 n2 -- n3 )
;
; Divide n1 by n2, giving the single-cell remainder n3.  An ambiguous
; condition exists if n2 is zero.  If n1 and n2 differ in sign, the
; implementation-defined result returned will be the same as that returned
; by either the phrase >R S>D R> FM/MOD DROP or the phrase
; >R S>D R> SM/REM DROP.
;
; ---
; : MOD ( n1 n2 -- n3)   /MOD DROP ;

            .linkTo min,0,3,'D',"OM"
mod JMP     enter
            .word   slashmod,drop,exit


; ----------------------------------------------------------------------
; MOVE [CORE] 6.1.1900 ( addr1 addr2 u -- )
;
; If u is greater than zero, copy the contents of u consecutive address
; units at addr1 to the u consecutive address units at addr2.  After MOVE
; completes, the u consecutive address units at addr2 contain exactly what
; the u consecutive address units at addr1 contained before the move.
;
; ---
; : MOVE ( addr1 addr2 u --)
;   >R 2DUP SWAP DUP R@ + WITHIN R> SWAP IF CMOVE> ELSE CMOVE THEN ;

            .linkTo mod,0,4,'E',"VOM"
move JMP     enter
            .word   tor,twodup,swap,dup,rfetch,plus,within
            .word   rfrom,swap,zbranch,_move1
            .word   cmoveup,exit
_move1 .word   cmove,exit


; ----------------------------------------------------------------------
; NEGATE [CORE] 6.1.1910 ( n1 -- n2 )
;
; Negate n1, giving its arithmetic inverse n2.  

            .linkTo move,0,6,'E',"TAGEN"
negate POP     H
            MOV     A,L
            CMA
            MOV     L,A
            MOV     A,H
            CMA
            MOV     H,A
            INX     H
            PUSH    H
            .next


; ----------------------------------------------------------------------
; OR [CORE] 6.1.1980 ( x1 x2 -- x3 )
;
; x3 is the bit-by-bit inclusive-or of x1 with x2.

            .linkTo negate,0,2,'R',"O"
or .saveDe
            POP     H           ; Pop x2.
            POP     D           ; Pop x1.
            MOV     A,H         ; Put x2's high byte into A,
            ORA     D           ; ..then OR x1's high byte with A,
            MOV     H,A         ; ..and put the result into H.
            MOV     A,L         ; Put x2's low byte into A,
            ORA     E           ; ..then OR x1's low byte with A,
            MOV     L,A         ; ..and put the result into L.
            PUSH    H           ; Push the result (HL).
            .restoreDe
            .next


; ----------------------------------------------------------------------
; OVER [CORE] 6.1.1990 ( x1 x2 -- x1 x2 x1 )
;
; Place a copy of x1 on top of the stack.

            .linkTo or,0,4,'R',"EVO"
over PUSH    D           ; Save DE on the stack.
            .byte 038H,    4           ; Get the address of the third stack item.
            .byte 0EDH                ; Load the third stack item into HL.
            POP     D           ; Restore DE.
            PUSH    H           ; Push the third stack item onto the stack.
            .next


; ----------------------------------------------------------------------
; POSTPONE [CORE] 6.1.2033
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( "<spaces>name" -- )
;   Skip leading space delimiters.  Parse name delimited by a space.  Find
;   name.  Append the compilation semantics of name to the current
;   definition.  An ambiguous condition exists if name is not found.
;
; ---
; Postponing a non-immediate word requires the compiler to add code to the
; current definition that compiles the postponed word into the then-current
; definition when the current definition is executed.  Postponing an
; immediate word requires the word to be compiled directly into the current
; definition.
;
; : POSTPONE ( "<spaces>name" --)
;   PARSE-WORD (FIND)  DUP 0= IF DROP TYPE SPACE [CHAR] ? EMIT CR ABORT THEN
;   0< IF  ['] LIT COMPILE,  ,  ['] COMPILE, COMPILE, ELSE COMPILE, THEN
; ; IMMEDIATE

            .linkTo over,1,8,'E',"NOPTSOP"
postpone JMP     enter
            .word   parseword,pfind,dup,zeroequals,zbranch,_postpone1
            .word   drop,type,space,lit,'?',emit,cr,abort
_postpone1 .word   zeroless,zbranch,_postpone2
            .word   lit,lit,compilecomma,comma,lit,compilecomma,compilecomma
            .word       branch,_postpone3
_postpone2 .word   compilecomma
_postpone3 .word   exit


; ----------------------------------------------------------------------
; QUIT [CORE] 6.1.2050 ( -- ) ( R:  i*x -- )
;
; Empty the return stack, store zero in SOURCE-ID if it is present, make
; the user input device the input source, and enter interpretation state.
; Do not display a message.  Repeat the following:
;   - Accept a line from the input source into the input buffer, set >IN
;     to zero, and interpret.
;   - Display the implementation-defined system prompt if in interpretation
;     state, all processing has been completed, and no ambiguous condition
;     exists.
;
; ---
; : QUIT  ( --; R: i*x --)
;   INITRP  0 STATE !  INIT-ICBS  TIB  ICB ICBLINESTART +  !
;   BEGIN
;       TIB TIBSIZE  ACCEPT  TIB +  ICB ICBLINEEND + !
;       SPACE INTERPRET
;       CR  STATE @ 0= IF ." ok " THEN
;   AGAIN ;

            .linkTo postpone,0,4,'T',"IUQ"
quit JMP     enter
            .word   initrp
            .word   zero,state,store
            .word   initicbs,tib,icb,lit,icblinestart,plus,store
_quit1 .word   tib,lit,tibsize,accept
            .word   tib,plus,icb,lit,icblineend,plus,store
            .word   space,interpret
            .word   cr,state,fetch,zeroequals,zbranch,_quit2
            .word   psquote,3
            .byte   "ok "
            .word   type
_quit2 .word   branch,_quit1


; ----------------------------------------------------------------------
; R> [CORE] 6.1.2060 "r-from"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( -- x ) ( R: x -- )
;   Move x from the return stack to the data stack.

            .linkTo quit,0,2,'>',"R"
rfrom .rsPop H,L
            PUSH    H
            .next


; ----------------------------------------------------------------------
; R@ [CORE] 6.1.2070 "r-fetch"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( -- x ) ( R: x -- x )
;   Copy x from the return stack to the data stack.

            .linkTo rfrom,0,2,'@',"R"
rfetch .rsFetch H,L
            PUSH    H
            .next


; ----------------------------------------------------------------------
; RECURSE [CORE] 6.1.2120
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( -- )
;   Append the execution semantics of the current definition to the current
;   definition.  An ambiguous condition exists if RECURSE appears in a
;   definition after DOES>.
;
; ---
; RECURSE   LATEST @ NFA>CFA , ; IMMEDIATE

            .linkTo rfetch,1,7,'E',"SRUCER"
recurse JMP     enter
            .word   latest,fetch,nfatocfa,comma,exit


; ----------------------------------------------------------------------
; REPEAT [CORE] 6.1.2140
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: orig dest -- )
;   Append the run-time semantics given below to the current definition,
;   resolving the backward reference dest.  Resolve the forward reference
;   orig using the location following the appended run-time semantics.
;
; Run-time: ( -- )
;   Continue execution at the location given by dest.
;
; ---
; REPEAT   POSTPONE AGAIN  POSTPONE THEN ; IMMEDIATE

            .linkTo recurse,1,6,'T',"AEPER"
repeat JMP     enter
            .word   again,then,exit


; ----------------------------------------------------------------------
; ROT [CORE] 6.1.2160 "rote" ( x1 x2 x3 -- x2 x3 x1 )
;
; Rotate the top three stack entries.

            .linkTo repeat,0,3,'T',"OR"
rot .saveDe
            POP     D           ; Pop x3 into DE.
            POP     H           ; Pop x2 into HL.
            XTHL                ; Swap TOS (x1) with HL (x2).
            PUSH    D           ; Push x3 back onto the stack.
            PUSH    H           ; Push x1 back onto the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; RSHIFT [CORE] 6.1.1805 "l-shift" ( x1 u -- x2 )
;
; Perform a logical left shift of u bit-places on x1, giving x2.  Put
; zeroes into the least significant bits vacated by the shift.  An
; ambiguous condition exists if u is greater than or equal to the number
; of bits in a cell.

            .linkTo rot,0,6,'T',"FIHSR"
rshift .saveDe
            POP     D           ; Pop u into DE, although we only care about E.
            POP     H           ; Pop x1 into HL.
            INR     E           ; Increment E so that the loop can pre-test.
_rshift1 DCR     E           ; Decrement E and see if the count is zero;
            JZ      _rshiftdone ; ..we're done if so.
            ANA     A           ; Clear carry.
            MOV     A,H         ; Move the high byte into A,
            RAR                 ; ..rotate right with carry,
            MOV     H,A         ; ..then put the high byte back into H.
            MOV     A,L         ; Move the low byte into A,
            RAR                 ; ..rotate right with carry,
            MOV     L,A         ; ..then put the low byte back into L.
            JMP     _rshift1    ; Continue looping.
_rshiftdone PUSH    H           ; Push the result (HL).
            .restoreDe
            .next


; ----------------------------------------------------------------------
; S" [CORE] 6.1.2165 "s-quote"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
;   Extended by FILE: ( "ccc<quote>" -- c-addr u )
;       Parse ccc delimited by " (double quote).  Store the resulting
;       string c-addr u at a temporary location.  The maximum length of
;       the temporary buffer is implementation-dependent but shall be no
;       less than 80 characters.  Subsequent uses of S" may overwrite the
;       temporary buffer.  At least one such buffer shall be provided.
;
; Compilation: ( "ccc<quote>" -- )
;   Parse ccc delimited by " (double-quote).  Append the run-time
;   semantics given below to the current definition.
;
; Run-time: ( -- c-addr u )
;   Return c-addr and u describing a string consisting of the characters
;   ccc.  A program shall not alter the returned string.
;
; ---
; : S" ( "ccc<quote>" --)
;   [CHAR] " PARSE ( caS uS)
;   STATE @ 0= IF  DUP 'S"SIZE > ABORT" String too long"
;       'S" OVER 2SWAP ( caD uS caS uS)  'S"
;   ELSE ['] (S") COMPILE,  DUP ,  HERE OVER ALLOT THEN
;   ( caS uS caD) SWAP CMOVE ;

            .linkTo rshift,1,2,022H,"S"
squote JMP     enter
            .word   lit,022H,parse,state,fetch,zeroequals,zbranch,_squote2
            .word   dup,lit,sqsize,greaterthan,zbranch,_squote1
            .word   psquote,12
            .byte   "String too long"
            .word   type,abort
_squote1 .word   ticksquote,over,twoswap,ticksquote,branch,_squote3
_squote2 .word   lit,psquote,compilecomma,dup,comma,here,over,allot
_squote3 .word   swap,cmove,exit


; ----------------------------------------------------------------------
; S>D [CORE] 6.1.2170 "s-to-d" ( n -- d )
;
; Convert the number n to the double-cell number d with the same numerical value.
;
; ---
; : S>D ( n -- d)   DUP 0< ;

            .linkTo squote,0,3,'D',">S"
stod JMP     enter
            .word   dup,zeroless,exit


; ----------------------------------------------------------------------
; SIGN [CORE] 6.1.2210 ( n -- )
;
; If n is negative, add a minus sign to the beginning of the pictured
; numeric output string.  An ambiguous condition exists if SIGN executes
; outside of a <# #> delimited number conversion.
;
; ---
; : SIGN ( n -- )   0< IF 45 HOLD THEN ;

            .linkTo stod,0,4,'N',"GIS"
sign JMP     enter
            .word   zeroless,zbranch,_signdone,lit,45,hold
_signdone .word   exit


; ----------------------------------------------------------------------
; SM/REM [CORE] 6.1.2214 "s-m-slash-rem" ( d1 n1 -- n2 n3 )
;
; Divide d1 by n1, giving the symmetric quotient n3 and the remainder n2.
; Input and output stack arguments are signed.  An ambiguous condition
; exists if n1 is zero or if the quotient lies outside the range of a
; single-cell signed integer.
;
; ---
; : SM/REM ( d1 n1 -- n2 n3)
;   OVER >R  2DUP XOR >R  ( R:remsign quosign)
;   ABS >R DABS R>
;   UM/MOD ( +rem +quo)
;   R> ?NEGATE ( +rem +-quo)  SWAP R> ?NEGATE SWAP ( +-rem +-quo) ;

            .linkTo sign,0,6,'M',"ER/MS"
smslashrem JMP     enter
            .word   over,tor,twodup,xor,tor,abs,tor,dabs,rfrom,umslashmod
            .word   rfrom,qnegate,swap,rfrom,qnegate,swap,exit


; ----------------------------------------------------------------------
; SOURCE [CORE] 6.1.2216 ( -- c-addr u )
;
; c-addr is the address of, and u is the number of characters in, the
; input buffer.
;
; ---
; : SOURCE ( -- c-addr u)   ICB 2@ OVER - ;

            .linkTo smslashrem,0,6,'E',"CRUOS"
source JMP     enter
            .word   icb,twofetch,over,minus,exit


; ----------------------------------------------------------------------
; SPACE [CORE] 6.1.2220 ( -- )
;
; Display one space.

            .linkTo source,0,5,'E',"CAPS"
space MVI     A,020H      ; Put the space character in A.
            CALL    stdcall     ; Call the
            .word   04B44H      ; .."character output" routine.
            .next


; ----------------------------------------------------------------------
; SPACES [CORE] 6.1.2230 ( n -- )
;
; If n is greater than zero, display n spaces.
;
; ---
; : SPACES ( n -- )   DUP IF SPACE 1- THEN DROP ;

            .linkTo space,0,6,'S',"ECAPS"
spaces JMP     enter
_spaces1 .word   dup,zbranch,_spacesdone,space,oneminus,branch,_spaces1
_spacesdone .word   drop
            .word   exit


; ----------------------------------------------------------------------
; STATE [CORE] 6.1.2250 ( -- a-addr )
;
; a-addr is the address of a cell containing the compilation-state flag.
; STATE is true when in compilation state, false otherwise.  The true
; value in STATE is non-zero, but is otherwise implementation-defined.
; Only the following standard words alter the value in STATE:  : (colon),
; ; (semicolon), ABORT, QUIT, :NONAME, [ (left-bracket), and ] (right-bracket).
;
; Note: A program shall not directly alter the contents of STATE.

            .linkTo spaces,0,5,'E',"TATS"
state LXI     H,tickstate
            PUSH    H
            .next


; ----------------------------------------------------------------------
; SWAP [CORE] 6.1.2260 "two-dupe" ( x1 x2 -- x2 x1 )
;
; Exchange the top two stack items.

            .linkTo state,0,4,'P',"AWS"
swap POP     H           ; Pop x2 into HL.
            XTHL                ; Swap TOS (x1) with HL (x2).
            PUSH    H           ; Push x1 back onto the stack.
            .next


; ----------------------------------------------------------------------
; THEN [CORE] 6.1.2270
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( C: orig -- )
;   Append the run-time semantics given below to the current definition.
;   Resolve the forward reference orig using the location of the appended
;   run-time semantics.
;
; Run-time: ( -- )
;   Continue execution.
;
; ---
; : THEN   HERE SWAP ! ; IMMEDIATE

            .linkTo swap,1,4,'N',"EHT"
then JMP     enter
            .word   here,swap,store,exit


; ----------------------------------------------------------------------
; TYPE [CORE] 6.1.2310 ( c-addr u -- )
;
; If u is greater than zero, display the character string specified by
; c-addr and u.
;
; When passed a character in a character string whose character-defining
; bits have a value between hex 20 and 7E inclusive, the corresponding
; standard character, specified by 3.1.2.1 graphic characters, is displayed.
; Because different output devices can respond differently to control
; characters, programs that use control characters to perform specific
; functions have an environmental dependency.

            .linkTo then,0,4,'E',"PYT"
type .saveDe
            POP     D           ; Pop the count into DE.
            POP     H           ; Pop the address into HL.
_type1 MOV     A,D         ; See if the count is zero by moving D to A
            ORA     E           ; ..and then ORing A with E.
            JZ      _typedone   ; We're done if the count is zero.
            MOV     A,M         ; Get the current character.
            CALL    stdcall     ; Call the
            .word   04B44H      ; .."character output" routine.
            INX     H           ; Move to the next character.
            DCX     D           ; Decrement the remaining count.
            JMP     _type1      ; Keep going.
_typedone .restoreDe
            .next


; ----------------------------------------------------------------------
; U. [CORE] 6.1.2320 "u-dot" ( u -- )
;
; Display u in free field format.
;
; ---
; : U. ( u -- )   0 UD.

            .linkTo type,0,2,'.',"U"
udot JMP     enter
            .word   zero,uddot,exit


; ----------------------------------------------------------------------
; U< [CORE] 6.1.2340 "u-less-than" ( u1 u2 -- flag )
;
; flag is true if and only if u1 is less than u2.

            .linkTo udot,0,2,'<',"U"
ulessthan .saveDe
            POP     D           ; Pop u2.
            POP     H           ; Pop u1.
            PUSH    B           ; Save BC.
            MOV     B,D         ; Move u2
            MOV     C,E         ; ..to BC.
            .byte 08H                ; HL=u1-u2
            POP     B           ; Restore BC.
            SBB     A           ; Propagate carry throughout A
            MOV     H,A         ; ..and fill HL
            MOV     L,A         ; ..with the contents of A (0000 or FFFF).
            PUSH    H           ; Push the flag to the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; UM* [CORE] 6.1.2360 "u-m-star" ( u1 u2 -- ud )
;
; Multiply u1 by u2, giving the unsigned double-cell product ud.  All
; values and arithmetic are unsigned
;
; ---
; This is U* copied verbatim from fig-FORTH 8080 v1.3.
; The only changes were to save and restore DE in HOLDD.  BC was already
; getting saved since that is the fig-FORTH Instruction Pointer.  The
; fig-FORTH comments are unchanged, so replace "IP" with "RSP".

            .linkTo ulessthan,0,3,'*',"MU"
umstar .saveDe

            ; fig-FORTH code:
            POP     D           ; (DE) <- MPLIER
            POP     H           ; (HL) <- MPCAND
            PUSH    B           ; SAVE IP
            MOV     B,H
            MOV     A,L         ; (BA) <- MPCAND
            CALL    mpyx        ; (AHL)1 <- MPCAND.LB * MPLIER
            ; 1ST PARTIAL PRODUCT
            PUSH    H           ; SAVE (HL)1
            MOV     H,A
            MOV     A,B
            MOV     B,H         ; SAVE (A)1
            CALL    mpyx        ; (AHL)2 <- MPCAND.HB * MPLIER
            ; 2ND PARTIAL PRODUCT
            POP     D           ; (DE) <- (HL)1
            MOV     C,D         ; (BC) <- (AH)1
            ; FORM SUM OF PARTIALS:
            ;      (AHL) 1
            ;    + (AHL) 2
            ;   --------
            ;     (AHLE)
            DAD     B           ; (HL) <- (HL)2 + (AH)1
            ACI     0           ; (AHLE) <- (BA) * (DE)
            MOV     D,L
            MOV     L,H
            MOV     H,A         ; (HLDE) <- MPLIER * MPCAND
            POP     B           ; RESTORE IP
            PUSH    D           ; (S2) <- PRODUCT.LW

            ; MFORTH code:
            PUSH    H           ; (S1) <- PRODUCT.HW
            .restoreDe
            .next
            ;
            ;   MULTIPLY PRIMITIVE
            ;           (AHL) <- (A) * (DE)
            ;   #BITS =   24      8     16
mpyx LXI     H,0         ; (HL) <- 0 = PARTIAL PRODUCT.LW
            MVI     C,4         ; LOOP COUNTER
mpyx1 DAD     H           ; LEFT SHIFT (AHL) 24 BITS
            RAL
            JNC     mpyx2       ; IF NEXT MPLIER BIT = 1
            DAD     D           ; THEN ADD MPCAND
            ACI     0
mpyx2 DAD     H
            RAL
            JNC     mpyx3
            DAD     D
            ACI     0
mpyx3 DCR     C           ; IF NOT LAST MPLIER BIT
            JNZ     mpyx1       ; THEN LOOP AGAIN
            RET                 ; ELSE DONE


; ----------------------------------------------------------------------
; UM/MOD [CORE] 6.1.2370 "u-m-slash-mod" ( ud u1 -- u2 u3 )
;
; Divide ud by u1, giving the quotient u3 and the remainder u2.  All values
; and arithmetic are unsigned.  An ambiguous condition exists if u1 is zero
; or if the quotient lies outside the range of a single-cell unsigned integer.
;
; ---
; This is U/ copied verbatim from fig-FORTH 8080 v1.3.
; The only changes were to save and restore DE in HOLDD.  BC was already
; getting saved since that is the fig-FORTH Instruction Pointer.  The
; fig-FORTH comments are unchanged, so replace "IP" with "RSP".

            .linkTo umstar,0,6,'D',"OM/MU"
umslashmod .saveDe

            ; fig-FORTH code:
            MOV     H,B
            MOV     L,C         ; (HL) <- (IP)
            POP     B           ; (BC) <- (S1) = DENOMINATOR
            POP     D           ; (DE) <- (S2) = NUMERATOR.HIGH
            XTHL                ; (S1) <- (IP)
            XCHG                ; (HLDE) = NUMERATOR, 32 BITS
            MOV     A,L
            SUB     C
            MOV     A,H         ; IF OVERFLOW
            SBB     B
            JNC     usbad       ; THEN RETURN BAD VALUE
            MOV     A,H
            MOV     H,L
            MOV     L,D         ; (AHL) <- 24 BITS OF NUMERATOR
            MVI     D,8         ; (D) <- INIT COUNTER
            PUSH    D           ; SAVE D & E
            CALL    usla        ; PARTIAL DIVISION
            POP     D           ; RESTORE COUNTER & NUM.MSBYTE
            PUSH    H           ; (S1) <- (L) = BYTE OF QUOTIENT
            MOV     L,E
            CALL    usla
            MOV     D,A
            MOV     E,H         ; (DE) <- REMAINDER
            POP     B           ; RESTORE QUOTIENT.HIGH
            MOV     H,C         ; (HL) <- QUOTIENT
            POP     B           ; RESTORE (IP)

            ; MFORTH code:
            PUSH    D
            PUSH    H
            .restoreDe
            .next

usl0 MOV     E,A
            MOV     A,H
            SUB     C
            MOV     H,A
            MOV     A,E
            SBB     B
            JNC     usl1        ; IF CARRY
            MOV     A,H         ; THEN ADD (BC) INTO (AH)
            ADD     C
            MOV     H,A
            MOV     A,E
            DCR     D
            RZ                  ; RETURN FROM USLA

usla DAD     H           ; 24BIT LEFT-SHIFT ( *2 )
            RAL
            JNC     usl0        ; SUBTRACT & TEST
            MOV     E,A
            MOV     A,H
            SUB     C           ; (AH) <- (AH) - (BC)
            MOV     H,A
            MOV     A,E
            SBB     B
usl1 INR     L           ; 1 BIT OF QUOT INTO RIGHT SIDE
            DCR     D           ;   OF (AHL)
            JNZ     usla        ; CONTINUE DIVISION
            RET                 ; ALL 8 TRIAL COMPLETE

usbad LXI     H,0FFFFH    ; OVERFLOW, RETURN 32BIT -1
            POP     B           ; RESTORE (IP)

            ; MFORTH code:
            PUSH    H
            .restoreDe
            .next


; ----------------------------------------------------------------------
; UNLOOP [CORE] 6.1.2380
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( -- ) ( R: loop-sys -- )
;   Discard the loop-control parameters for the current nesting level.
;   An UNLOOP is required for each nesting level before the definition may
;   be EXITed.  An ambiguous condition exists if the loop-control parameters
;   are unavailable.
;
; ---
; UNLOOP  R> DROP R> DROP ;

            .linkTo umslashmod,0,6,'P',"OOLNU"
unloop .rsPop H,L
            .rsPop H,L
            .next


; ----------------------------------------------------------------------
; UNTIL [CORE] 6.1.2390
;
; Compilation: ( C: dest -- )
;   Append the run-time semantics given below to the current definition,
;   resolving the backward reference dest.
;
; Run-time: ( x -- )
;   If all bits of x are zero, continue execution at the location specified
;   by dest.
;
; ---
; : UNTIL   ['] 0branch COMPILE,  , ; IMMEDIATE

            .linkTo unloop,1,5,'L',"ITNU"
until JMP     enter
            .word   lit,zbranch,compilecomma,comma,exit


; ----------------------------------------------------------------------
; VARIABLE [CORE] 6.1.2410 ( "<spaces>name" -- )
;
; Skip leading space delimiters.  Parse name delimited by a space.  Create
; a definition for name with the execution semantics defined below.  Reserve
; one cell of data space at an aligned address.
;
; name is referred to as a "variable".
;
; name Execution: ( -- a-addr )
;   a-addr is the address of the reserved cell.  A program is responsible
;   for initializing the contents of the reserved cell.
;
; ---
; : VARIABLE ( "<spaces>name" -- )
;   CREATE  CFASZ NEGATE ALLOT  195 C, DOVARIABLE ,  0 , ; -- JMP DOVARIABLE

            .linkTo until,0,8,'E',"LBAIRAV"
variable JMP     enter
            .word   create,lit,-cfasz,allot,lit,195,ccomma,lit,dovariable,comma
            .word   zero,comma,exit


; ----------------------------------------------------------------------
; WHILE [CORE] 6.1.2430
;
; Compilation: ( C: dest -- orig dest )
;   Put the location of a new unresolved forward reference orig onto the
;   control flow stack, under the existing dest.  Append the run-time
;   semantics given below to the current definition.  The semantics are
;   incomplete until orig and dest are resolved (e.g., by REPEAT).
;
; Run-time: ( x -- )
;   If all bits of x are zero, continue execution at the location specified
;   by the resolution of orig.
;
; ---
; : WHILE   POSTPONE IF  SWAP ; IMMEDIATE

            .linkTo variable,1,5,'E',"LIHW"
while JMP     enter
            .word   if,swap,exit


; ----------------------------------------------------------------------
; WORD [CORE] 6.1.2450 ( char "<chars>ccc<char>" -- c-addr )
;
; Skip leading delimiters.  Parse characters ccc delimited by char.  An
; ambiguous condition exists if the length of the parsed string is greater
; than the implementation-defined length of a counted string.
;
; c-addr is the address of a transient region containing the parsed word as
; a counted string.  If the parse area was empty or contained no characters
; other than the delimiter, the resulting string has a zero length.  A space,
; not included in the length, follows the string.  A program may replace
; characters within the string.
;
; Note: The requirement to follow the string with a space is obsolescent and
; is included as a concession to existing programs that use CONVERT.  A
; program shall not depend on the existence of the space.
;
; ---
; : WORD ( char "<chars>ccc<char>" -- c-addr)
;   TRUE SWAP (parse) >R 'WORD 1+ R@ CMOVE
;   R@ 'WORD C!  BL 'WORD 1+ R> + C!
;   'WORD ;

            .linkTo while,0,4,'D',"ROW"
word JMP     enter
            .word   true,swap,pparse,tor,tickword,oneplus,rfetch,cmove
            .word   rfetch,tickword,cstore,bl,tickword,oneplus,rfrom,plus,cstore
            .word   tickword,exit


; ----------------------------------------------------------------------
; XOR [CORE] 6.1.2490 ( x1 x2 -- x3 )
;
; x3 is the bit-by-bit exclusive-or of x1 with x2.

            .linkTo word,0,3,'R',"OX"
xor .saveDe
            POP     H           ; Pop x2.
            POP     D           ; Pop x1.
            MOV     A,H         ; Put x2's high byte into A,
            XRA     D           ; ..then XOR x1's high byte with A,
            MOV     H,A         ; ..and put the result into H.
            MOV     A,L         ; Put x2's low byte into A,
            XRA     E           ; ..then XOR x1's low byte with A,
            MOV     L,A         ; ..and put the result into L.
            PUSH    H           ; Push the result (HL).
            .restoreDe
            .next


; ----------------------------------------------------------------------
; [ [CORE] 6.1.2500 "left-bracket" ( -- )
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation:
;   Perform the execution semantics given below.
;
; Execution: ( -- )
;   Enter interpretation state.  [ is an immediate word.

            .linkTo0 xor,1,1,'['
ltbracket LXI     H,0
            SHLD    tickstate
            .next


; ----------------------------------------------------------------------
; ['] [CORE] 6.1.2510 "bracket-tick"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( "<spaces>name" -- )
;   Skip leading space delimiters.  Parse name delimited by a space.
;   Find name.  Append the run-time semantics given below to the current
;   definition.
;
;   An ambiguous condition exists if name is not found.
;
; Run-time: ( -- xt )
;   Place name's execution token xt on the stack.  The execution token
;   returned by the compiled phrase "['] X " is the same value returned by
;   "' X " outside of compilation state.
;
; ---
; : ['] ( "<spaces>name" -- )   '  ['] LIT COMPILE,  , ; IMMEDIATE

            .linkTo ltbracket,1,3,']',"\'["
brackettick JMP     enter
            .word   tick,lit,lit,compilecomma,comma,exit


; ----------------------------------------------------------------------
; [CHAR] [CORE] 6.1.2520 "bracket-char"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( "<spaces>name" -- )
;   Skip leading space delimiters.  Parse name delimited by a space.
;   Append the run-time semantics given below to the current definition.
;
; Run-time: ( -- char )
;   Place char, the value of the first character of name, on the stack.
;
; ---
; : [CHAR] ( "<spaces>name" -- char)   CHAR  ['] LIT COMPILE,  , ; IMMEDIATE

            .linkTo brackettick,1,6,']',"RAHC["
bracketchar JMP     enter
            .word   char,lit,lit,compilecomma,comma,exit


; ----------------------------------------------------------------------
; ] [CORE] 6.1.2540 "right-bracket" ( -- )
;
; Enter compilation state.

            .linkTo0 bracketchar,0,1,']'
rtbracket LXI     H,0FFFFH
            SHLD    tickstate
            .next



; ======================================================================
; CORE Constants (implementation details)
; ======================================================================

; ----------------------------------------------------------------------
; Input Control Block
;
; Stores information about an input source.

icblineend =    0           ; Offset to end of line.
icblinestart =   2           ; Offset from ICB to start of line cell.
icbsourceid =    4           ; Offset to SOURCE-ID for this source.
icbtoin =    6           ; Offset to >IN value.


; ======================================================================
; CORE Words (implementation details)
; ======================================================================

; ----------------------------------------------------------------------
; 'S" [MFORTH] "tick-s-quote" ( -- addr )
;
; addr is the address of the start of the S" buffer.

            .linkTo rtbracket,0,3,022H,"S\'"
ticksquote LHLD    dp
            PUSH    D
            LXI     D,sqoffset
            DAD     D
            XTHL
            XCHG
            .next


; ----------------------------------------------------------------------
; 'WORD [MFORTH] "tick-word" ( -- addr )
;
; addr is the address of the start of the WORD buffer.

            .linkTo ticksquote,0,5,'D',"ROW\'"
tickword LHLD    dp
            PUSH    D
            LXI     D,wordoffset
            DAD     D
            XTHL
            XCHG
            .next


; ----------------------------------------------------------------------
; (?do) [MFORTH] "paren-question-do-paren" ( n1|u1 n2|u2 -- ) ( R: -- | loop-sys )
;
; If n1|u1 is equal to n2|u2, continue execution at the location given by
; the consumer of do-sys.  Otherwise set up loop control parameters with
; index n2|u2 and limit n1|u1 and continue executing immediately following
; ?DO.  Anything already on the return stack becomes unavailable until the
; loop control parameters are discarded.  An ambiguous condition exists if
; n1|u1 and n2|u2 are not both of the same type.

            .linkTo tickword,0,5,029H,"od?("
pqdo .saveDe
            POP     H           ; Pop index into HL.
            POP     D           ; Pop limit into DE.
            .rsPush D,E         ; Push limit onto return stack.
            .rsPush H,L         ; Push index onto return stack.
            PUSH    B           ; Save BC.
            MOV     B,D         ; Move the limit
            MOV     C,E         ; ..to BC.
            .byte 08H                ; HL=HL-BC
            POP     B           ; Restore BC.
            .restoreDe
            JNZ     _pqdobegin  ; Begin the loop if the values are not equal.
            .rsPop H,L          ; Remove the loop
            .rsPop H,L          ; ..items from the return stack.
            .byte 0EDH                ; Get the branch address into HL.
            XCHG                ; Swap the branch address into DE.
            JMP     _pqdodone   ; We're done.
_pqdobegin INX     D           ; Skip the
            INX     D           ; ..branch address.
_pqdodone .next


; ----------------------------------------------------------------------
; (do) [MFORTH] "paren-do-paren" ( n1|u1 n2|u2 -- ) ( R: -- loop-sys )
;
; Set up loop control parameters with index n2|u2 and limit n1|u1. An
; ambiguous condition exists if n1|u1 and n2|u2 are not both the same type.
; Anything already on the return stack becomes unavailable until the
; loop-control parameters are discarded.

            .linkTo pqdo,0,4,029H,"od("
pdo POP     H           ; Pop index into HL,
            XTHL                ; ..swap the index and the limit,
            .rsPush H,L         ; ..and push the limit onto the return stack.
            POP     H           ; Pop index into HL
            .rsPush H,L         ; ..and push the index onto the return stack.
            .next


; ----------------------------------------------------------------------
; (+loop) [MFORTH] "plus-loop" ( n -- ) ( R: loop-sys1 -- | loop-sys2 )
;
; An ambiguous condition exists if the loop control parameters are
; unavailable.  Add n to the loop index.  If the loop index did not cross
; the boundary between the loop limit minus one and the loop limit, continue
; execution at the beginning of the loop.  Otherwise, discard the current
; loop control parameters and continue execution immediately following the loop.  

            .linkTo pdo,0,7,029H,"pool+("
pplusloop .saveDe
            .rsPop H,L          ; Get the current loop index from the RS.
            POP     D           ; Get the increment from the stack.
            MOV     A,D         ; Move the high byte of the increment to A,
            ORA     A           ; ..see if the increment is positive or zero,
            PUSH    PSW         ; ..and then store the result on the stack.
            DAD     D           ; Increment the loop index.
            .rsFetch D,E        ; Get the loop limit from the RS
            .rsPush H,L         ; ..and put the new loop index back onto the RS.
            POP     PSW         ; See if the increment is positive or zero
            JP      _pplposincr ; ..and then calculate the flag appropriately.
_pplsnegincr PUSH   B           ; Save BC.
            MOV     B,D         ; Move the loop limit
            MOV     C,E         ; ..into BC.
            .byte 08H                ; Subtract the limit from the index.
            POP     B           ; Restore BC.
            JP      _pplcontinue; Continue if index was >= limit,
            JMP     _pplunloop  ; ..otherwise unloop.
_pplposincr PUSH    B           ; Save BC.
            MOV     B,D         ; Move the loop limit
            MOV     C,E         ; ..into BC.
            .byte 08H                ; Subtract the limit from the index.
            POP     B           ; Restore BC.
            JP      _pplunloop  ; Unloop if index was >= limit.
_pplcontinue .restoreDe
            .byte 0EDH                ; Get the branch address into HL.
            XCHG                ; Swap the branch address into DE.
            JMP     _ppldone    ; We're done.
_pplunloop .restoreDe
            .rsPop H,L          ; Pop the loop index.
            .rsPop H,L          ; Pop the loop limit.
            INX     D           ; Skip the
            INX     D           ; ..branch address.
_ppldone .next


; ----------------------------------------------------------------------
; (loop) [MFORTH] "paren-loop-paren" ( -- ) ( R: loop-sys1 -- | loop-sys2 )
;
; An ambiguous condition exists if the loop control parameters are
; unavailable.  Add one to the loop index.  If the loop index is then equal
; to the loop limit, discard the loop parameters and continue execution
; immediately following the loop.  Otherwise continue execution at the
; beginning of the loop.

            .linkTo pplusloop,0,6,029H,"pool("
ploop .saveDe
            .rsPop H,L          ; Get the current loop index from the RS
            INX     H           ; ..and increment the loop index.
            .rsFetch D,E        ; Get the loop limit from the RS
            .rsPush H,L         ; ..and put the new loop index back onto the RS.
            PUSH    B           ; Save BC.
            MOV     B,D         ; Move the loop limit
            MOV     C,E         ; ..into BC.
            .byte 08H                ; Subtract the limit from the index.
            POP     B           ; Restore BC.
            .restoreDe
            JZ      _ploopunloop; Loop is done if the values are equal (zero).
            .byte 0EDH                ; Get the branch address into HL.
            XCHG                ; Swap the branch address into DE.
            JMP     _ploopdone  ; We're done.
_ploopunloop .rsPop H,L         ; Pop the loop index.
            .rsPop H,L          ; Pop the loop limit.
            INX     D           ; Skip the
            INX     D           ; ..branch address.
_ploopdone .next


; ----------------------------------------------------------------------
; (s") [MFORTH] "paren-s-quote-paren" ( -- c-addr u )
;
; Runtime behavior of S": return c-addr and u.

            .linkTo ploop,0,4,029H,"\"s("
psquote .byte 0EDH                ; Read string count from instruction stream.
            INX     D           ; Skip over count
            INX     D           ; ..in instruction stream.
            PUSH    D           ; Push string address onto the stack.
            PUSH    H           ; Push string count onto the stack.
            XCHG                ; IP to HL, count to DE.
            DAD     D           ; Add count to address to skip over string.
            XCHG                ; Put IP back in DE (pointing after string).
            .next


; ----------------------------------------------------------------------
; 0 [MFORTH] "zero" ( -- 0 )
;
; Push zero onto the stack.

            .linkTo0 psquote,0,1,'0'
zero LXI     H,0
            PUSH    H
            .next


; ----------------------------------------------------------------------
; 0branch [MFORTH] "zero-branch" ( flag -- )
;
; If flag is false, then set the instruction pointer to the address that is
; in the next cell of the instruction stream, otherwise skip over the branch
; address and continue processing instructions.

            .linkTo zero,0,7,'h',"cnarb0"
zbranch POP     H           ; Get the flag.
            MOV     A,H         ; See if the flag is zero by moving H to A
            ORA     L           ; ..and then ORing A with L.
            JNZ     _zbratrue   ; True?  Skip the branch.
            .byte 0EDH                ; Get the branch address into HL.
            XCHG                ; Swap the branch address into DE.
            JMP     _zbradone   ; We're done.
_zbratrue INX     D           ; Skip the
            INX     D           ; ..branch address.
_zbradone .next


; ----------------------------------------------------------------------
; 1 [MFORTH] "one" ( -- 1 )
;
; Push one onto the stack.

            .linkTo0 zbranch,0,1,'1'
one LXI     H,1
            PUSH    H
            .next


; ----------------------------------------------------------------------
; >DIGIT [MFORTH] "to-digit" ( u -- char )
;
; char is the digit u converted to the values 0-9A-Z.
;
; ---
; >DIGIT ( u -- c ) DUP 9 > 7 AND + 48 + ;

            .linkTo one,0,6,'T',"IGID>"
todigit POP     H
            MOV     A,L
            CPI     00AH
            JC       _todigit2  ; u is < 10, so just add 030h for 0-9.
            ADI     7           ; u is >= 10, add an extra 7 to get to A-Z.
_todigit2 ADI     030H
            MOV     L,A
            PUSH    H
            .next


; ----------------------------------------------------------------------
; ?DNEGATE [MFORTH] ( d1 n -- d2 )
;
; Negate d1 if n is negative.
;
; ---
; : ?DNEGATE ( d1 n -- d2)   0< IF DNEGATE THEN ;

            .linkTo todigit,0,8,'E',"TAGEND?"
qdnegate JMP     enter
            .word   zeroless,zbranch,_dnegate1,dnegate
_dnegate1 .word   exit


; ----------------------------------------------------------------------
; ?NEGATE [MFORTH] ( n1 n2 -- n3 )
;
; Negate n1 if n2 is negative.
;
; ---
; : ?NEGATE ( n1 n2 -- n3)   0< IF NEGATE THEN ;

            .linkTo qdnegate,0,7,'E',"TAGEN?"
qnegate JMP     enter
            .word   zeroless,zbranch,_negate1,negate
_negate1 .word   exit


; ----------------------------------------------------------------------
; branch [MFORTH] ( -- )
;
; Set the instruction pointer to the address that is in the next cell of
; the instruction stream.

            .linkTo qnegate,0,6,'h',"cnarb"
branch .byte 0EDH                ; Get the branch address into HL.
            XCHG                ; Swap the branch address into DE.
            .next


; ----------------------------------------------------------------------
; DIGIT? [MFORTH] "digit-question" ( char -- u -1 | 0 )
;
; Attempts to convert char to a numeric value using the current BASE.
; Pushes the numeric value and -1 to the stack if the value was converted,
; otherwise pushes 0 to the stack.

            .linkTo branch,0,6,'?',"TIGID"
digitq MOV     H,B         ; Get the contents
            MVI     L,userbase  ; ..of the BASE
            MOV     L,M         ; ..user variable in L.
            XTHL                ; Swap the character with the BASE,
            MOV     A,L         ; ..move the character into A,
            POP     H           ; ..and then get the BASE back into L.
            SUI     030H        ; Is char > "0"
            CPI     00AH        ; ..and > "9"?
            JC      _digitq1    ; ..No: check the base and continue.
            SUI     7           ; Yes: subtract 7,
            CPI     00AH        ; ..make sure that the char is > "9"
            JC      _digitqflse ; ..and fail if not (char between "9" and "A").
_digitq1 CMP     L           ; Make sure that digit is less than BASE
            JNC     _digitqflse ; ..and fail if not.
            MOV     L,A         ; Move the digit to L,
            MVI     H,0         ; ..clear H,
            PUSH    H           ; ..and push the digit.
            LXI     H,0FFFFH    ; Put true in HL.
            JMP     _digitqdone ; We're done.
_digitqflse LXI     H,0         ; Put false in HL.
_digitqdone PUSH    H           ; Push the flag to the stack.
            .next


; ----------------------------------------------------------------------
; END-LOOP [MFORTH] ( do-orig pdo-xt -- )
;
; Completes the loop whose loop-sys parameters on the stack.  pdo-xt
; points to either (loop) or (+loop) and is compiled into the end of
; the loop.
;
; ---
; : END-LOOP ( do-orig pdo-xt)
;   COMPILE, ,  'PREVLEAVE @ HERE>CHAIN ; IMMEDIATE

endloop JMP     enter
            .word   compilecomma,comma
            .word   lit,tickprevleave,fetch,heretochain,exit


; ----------------------------------------------------------------------
; (FIND) [MFORTH] "paren-find-paren" ( c-addr u -- c-addr u 0 | xt 1 | xt -1 )
;
; Find the definition named in the string at c-addr with length u in the
; word list whose latest definition is pointed to by nfa.  If the
; definition is not found, return the string and zero.  If the
; definition is found, return its execution token xt.  If the definition
; is immediate, also return one (1), otherwise also return minus-one
; (-1).  For a given string, the values returned by FIND while compiling
; may differ from those returned while not compiling.
;
; ---
; : (FIND) ( c-addr u -- c-addr u 0 | xt 1 | xt -1 )
;   CONTEXT >R  BEGIN
;       2DUP R@ @ SEARCH-WORDLIST ( ca u 0 | ca u xt 1 | ca u xt -1)
;       ?DUP 0<> IF 2NIP R> DROP EXIT THEN ( ca u)
;       R> CELL+  DUP @ 0= IF DROP 0 EXIT THEN  >R
;   AGAIN ;

            .linkTo digitq,0,6,029H,"DNIF("
pfind JMP     enter
            .word   context,tor
_pfind1 .word   twodup,rfetch,fetch,searchwordlist
            .word   qdup,zeronotequals,zbranch,_pfind2
            .word   twonip,rfrom,drop,exit
_pfind2 .word   rfrom,cellplus,dup,fetch,zeroequals,zbranch,_pfind3
            .word   drop,zero,exit
_pfind3 .word   tor,branch,_pfind1


; ----------------------------------------------------------------------
; (KEY) [MFORTH] "paren-key-paren" ( -- char )
;
; Receive one character char, a member of the implementation-defined
; character set.  Keyboard events that do not correspond to such characters
; are discarded until a valid character is received, and those events are
; subsequently unavailable.
;
; All standard characters can be received.  Characters received by KEY are
; not displayed.
;
; Any standard character returned by KEY has the numeric value specified in
; 3.1.2.1 Graphic characters.  Programs that require the ability to receive
; control characters have an environmental dependency.
;
; ---
; TODO: Apparently the Model 100 does magical, special things here and can
; convert function keys to text (maybe we can use this as a macro feature?),
; and sets Carry when the key is "special".  We probably want to avoid "special"
; keys and just accept non-special keys.  For now we just take the easy route.

            .linkTo pfind,0,5,029H,"YEK("
pkey CALL    stdcall     ; Call the
            .word   012CBH      ; ..CHGET routine.
            MVI     H,0         ; Clear H,
            MOV     L,A         ; ..put the character in L,
            PUSH    H           ; ..and push the character onto the stack.
            .next


; ----------------------------------------------------------------------
; HERE>CHAIN [MFORTH] "here-to-chain" ( addr -- )
;
; Store HERE in the zero-terminated chain beginning at addr.  Each addr
; is expected to contain the addr of the previous element in the chain.
; The last element in the chain (which could be addr itself) should
; contain zero.
;
; ---
; HERE>CHAIN ( addr -- )
;   BEGIN ?DUP WHILE DUP @ HERE ( a a' h) ROT ! REPEAT ;

            .linkTo pkey,0,10,'N',"IAHC>EREH"
heretochain JMP     enter
_htc1 .word   qdup,zbranch,_htc2
            .word   dup,fetch,here,rot,store,branch,_htc1
_htc2 .word   exit


; ----------------------------------------------------------------------
; HIDDEN? [MFORTH] ( dict-addr -- flag )
;
; flag is true if and only if the given dictionary word is hidden.
;
; ---
; : HIDDEN ( dict-addr -- f )   C@ 64 AND 0<> ;

            .linkTo heretochain,0,7,'?',"NEDDIH"
hiddenq JMP     enter
            .word   cfetch,lit,64,and,zeronotequals,exit


; ----------------------------------------------------------------------
; HIDE [MFORTH] ( -- )
;
; Prevent the most recent definition from being found in the dictionary.
; ---
; : HIDE ( -- )   LATEST @  DUP C@ [HEX] 40 OR  SWAP C! ;

            .linkTo hiddenq,0,4,'E',"DIH"
hide JMP     enter
            .word   latest,fetch,dup,cfetch,lit,040H,or,swap,cstore,exit


; ----------------------------------------------------------------------
; HLD [MFORTH] "h-l-d" ( -- c-addr )
;
; c-addr is the address of the cell containing the current location in
; the Pictured Numeric Output hold buffer.

            .linkTo hide,0,3,'D',"LH"
hld LXI     H,tickhld
            PUSH    H
            .next


; ----------------------------------------------------------------------
; ICB [MFORTH] "i-c-b" ( -- c-addr )
;
; c-addr is the address of the current Input Control Block.

            .linkTo hld,0,3,'B',"CI"
icb LHLD    tickicb
            PUSH    H
            .next


; ----------------------------------------------------------------------
; INIT-ICBS [MFORTH] "init-icbs" ( -- )
;
; Initialize all of the Input Control Blocks.  The current Input Control
; Block should be configured immediately after executing this word.
;
; ---
; : INIT-ICBS ( -- )
;   ICBSTART [ MAXICBS 2* 2* 2* ] 0 FILL  ICBSTART TO ICB ;

            .linkTo icb,0,9,'S',"BCI-TINI"
initicbs JMP     enter
            .word   lit,icbstart,lit,maxicbs*8,zero,fill
            .word   lit,icbstart,lit,tickicb,store,exit


; ----------------------------------------------------------------------
; INTERPRET [MFORTH] ( i*x -- j*x )
;
; Interpret the line in the current Input Control Block.
;
; : INTERPRET ( i*x -- j*x )
;   0 >IN !
;   BEGIN  PARSE-WORD  DUP WHILE
;       (FIND) ( ca u 0=notfound | xt 1=imm | xt -1=interp)
;       ?DUP IF ( xt 1=imm | xt -1=interp)
;           1+  STATE @ 0=  OR ( xt 2=imm | xt 0=interp)
;           IF EXECUTE ELSE COMPILE, THEN
;       ELSE
;           NUMBER? IF
;               STATE @ IF POSTPONE LITERAL THEN
;               -- Interpreting; leave number on stack.
;           ELSE
;               TYPE  SPACE  [CHAR] ? EMIT  CR  ABORT
;           THEN
;       THEN
;   REPEAT ( j*x ca u) 2DROP ;

            .linkTo initicbs,0,9,'T',"ERPRETNI"
interpret JMP     enter
            .word   zero,toin,store
_interpret1 .word   parseword,dup,zbranch,_interpret6
            .word   pfind,qdup,zbranch,_interpret3
            .word   oneplus,state,fetch,zeroequals,or,zbranch,_interpret2
            .word   execute,branch,_interpret5
_interpret2 .word   compilecomma,branch,_interpret5
_interpret3 .word   numberq,zbranch,_interpret4
            .word   state,fetch,zbranch,_interpret5
            .word   literal,branch,_interpret5
_interpret4 .word   type,space,lit,'?',emit,cr,abort
_interpret5 .word   branch,_interpret1
_interpret6 .word   twodrop
            .word   exit


; ----------------------------------------------------------------------
; LATEST [MFORTH] "latest" ( -- a-addr )
;
; a-addr is the address of a cell containing the address of the link
; field of the latest word added to the dictionary.

            .linkTo interpret,0,6,'T',"SETAL"
latest JMP     enter
            .word   getcurrent,exit


; ----------------------------------------------------------------------
; LIT [MFORTH] ( -- x)
;
; Push the next value in the PFA to the stack.

            .linkTo latest,0,3,'T',"IL"
lit .byte 0EDH            ; Read constant from instruction stream.
            PUSH    H       ; ..and push constant to stack.
            INX     D       ; Skip over constant
            INX     D       ; ..in instruction stream.
            .next


; ----------------------------------------------------------------------
; NFA>CFA [MFORTH] "n-f-a-to-c-f-a" ( nfa-addr -- cfa-addr )
;
; cfa-addr is the Code Field Address for the word whose Name Field Address
; is nfa-addr.
;
; ---
; : NFA>CFA ( nfa-addr -- cfa-addr)   NFATOCFASZ + ;

            .linkTo lit,0,7,'A',"FC>AFN"
nfatocfa POP     H
            .inxNfaToCfa H
            PUSH    H
            .next


; ----------------------------------------------------------------------
; NFA>LFA [MFORTH] "n-f-a-to-l-f-a" ( nfa-addr -- lfa-addr )
;
; lfa-addr is the Link Field Address for the word whose Name Field Address
; is nfa-addr.
;
; ---
; : NFA>LFA ( nfa-addr -- lfa-addr)   1+ ;

            .linkTo nfatocfa,0,7,'A',"FL>AFN"
nfatolfa POP     H
            INX     H
            PUSH    H
            .next


; ----------------------------------------------------------------------
; NUMBER? [MFORTH] "number-question" ( c-addr u -- c-addr u 0 | n -1 )
;
; Attempt to convert a string at c-addr of length u into digits, using
; the radix in BASE.  The number and -1 is returned if the conversion
; was successful, otherwise 0 is returned.
;
; ---
; : NUMBER? ( ca u -- ca u 0 | n -1 )
;   SIGN? >R  2DUP 0 0 2SWAP  >NUMBER  ( ca u ud ca2 u2)
;   IF DROP 2DROP  R> DROP  0 ELSE
;      DROP 2NIP DROP  >R ?NEGATE  -1 THEN ;

            .linkTo nfatolfa,0,7,'?',"REBMUN"
numberq JMP     enter
            .word   signq,tor,twodup,zero,zero,twoswap
            .word       tonumber,zbranch,_numberq1
            .word   drop,twodrop,rfrom,drop,zero,branch,_numberq2
_numberq1 .word   drop,twonip,drop,rfrom,qnegate,lit,0FFFFH
_numberq2 .word   exit


; ----------------------------------------------------------------------
; POPICB [MFORTH] "push-i-c-b" ( -- )
;
; Point ICB at the previous Input Control Block.
;
; ---
; : POPICB ( --)  ICB 8 - TO ICB ;

            .linkTo numberq,0,6,'B',"CIPOP"
popicb JMP     enter
            .word   icb,lit,8,minus,lit,tickicb,store,exit


; ----------------------------------------------------------------------
; PUSHICB [MFORTH] "push-i-c-b" ( -- )
;
; Point ICB at the next Input Control Block.
;
; ---
; : PUSHICB ( --)  ICB 8 + TO ICB ;

            .linkTo popicb,0,7,'B',"CIHSUP"
pushicb JMP     enter
            .word   icb,lit,8,plus,lit,tickicb,store,exit


; ----------------------------------------------------------------------
; REVEAL [MFORTH] ( -- )
;
; Allow the most recent definition to be found in the dictionary.
;
; ---
; : REVEAL ( -- )   LATEST @  DUP C@ [HEX] BF AND  SWAP C! ;

            .linkTo pushicb,0,6,'L',"AEVER"
reveal JMP     enter
            .word   latest,fetch,dup,cfetch,lit,0BFH,and,swap,cstore,exit


; ----------------------------------------------------------------------
; SIGN? [MFORTH] "sign-question" ( c-addr1 u1 -- c-addr2 u2 flag )
;
; 
; Attempt to convert a string at c-addr of length u into digits, using
; the radix in BASE.  The number and -1 is returned if the conversion
; was successful, otherwise 0 is returned.
;
; ---
; : SIGN? ( ca1 u1 -- ca2 u2 f )
;   OVER  C@  DUP [CHAR] - =  OVER [CHAR] + = OR  IF
;       [CHAR] - = IF -1 ELSE 0 THEN  >R 1 /STRING R>
;   ELSE DROP 0 THEN ;

            .linkTo reveal,0,5,'?',"NGIS"
signq JMP     enter
            .word   over,cfetch,dup,lit,'-',equals,over,lit,'+',equals,or
            .word       zbranch,_signq3
            .word   lit,'-',equals,zbranch,_signq1,lit,0FFFFH,branch,_signq2
_signq1 .word   zero
_signq2 .word   tor,one,slashstring,rfrom,branch,_signq4
_signq3 .word   drop,zero
_signq4 .word   exit


; ----------------------------------------------------------------------
; UD* [MFORTH] "u-d-star" ( ud1 u1 -- ud2 )
;
; Multiply ud1 by u1, giving the unsigned double-cell product ud2.
;
; ---
; UD* ( ud1 u1 -- ud2)   DUP >R UM* DROP  SWAP R> UM* ROT + ;

            .linkTo signq,0,3,'*',"DU"
udstar JMP     enter
            .word   dup,tor,umstar,drop
            .word   swap,rfrom,umstar,rot,plus
            .word   exit


; ----------------------------------------------------------------------
; UD. [MFORTH] "u-d-dot" ( ud -- )
;
; Display ud in free field format.
;
; ---
; : UD. ( ud -- )   <# #S #> TYPE SPACE ;

            .linkTo udstar,0,3,'.',"DU"
uddot JMP     enter
            .word   lessnumsign,numsigns,numsigngrtr,type,space
            .word   exit


; ----------------------------------------------------------------------
; UD/MOD [MFORTH] "u-d-slash-mod" ( ud1 u1 -- n ud2 )
;
; Divide ud1 by u1 giving the quotient ud2 and the remainder n.
;
; ---
; UD/MOD ( ud1 u1 -- n ud2 )   >R 0 R@ UM/MOD  R> SWAP >R UM/MOD R> ;

            .linkTo uddot,0,6,'D',"OM/DU"
last_core
udslashmod JMP     enter
            .word   tor,zero,rfetch,umslashmod
            .word   rfrom,swap,tor,umslashmod,rfrom
            .word   exit
