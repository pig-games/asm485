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
; CORE EXT Words
; ======================================================================

; ----------------------------------------------------------------------
; .( [CORE EXT] 6.2.0200 "dot-paren"
;
; Compilation:
;   Perform the execution semantics given below.
;
; Execution: ( "ccc<paren>" -- )
;   Parse and display ccc delimited by ) (right parenthesis).  .( is an
;   immediate word.
;
; ---
; : .( "ccc<paren>" --)   [CHAR] ) PARSE TYPE ; IMMEDIATE

            .linkTo link_coreext,1,2,028H,"."
dotparen JMP     enter
            .word   lit,')',parse,type,exit


; ----------------------------------------------------------------------
; 0<> [CORE EXT] 6.2.0260 "zero-not-equals" ( x -- flag )
;
; flag is true if and only if x is not equal to zero.

            .linkTo dotparen,0,3,'>',"<0"
zeronotequals POP   H           ; Pop the value.
            MOV     A,H         ; See if the flag is zero by moving H to A
            ORA     L           ; ..and then ORing A with L.
            JZ      _zneqfalse  ; Jump if zero to where we push false.
            LXI     H,0FFFFH    ; Put true in HL.
            JMP     _zneqdone   ; We're done.
_zneqfalse LXI     H,0         ; Put false in HL.
_zneqdone PUSH    H           ; Push the flag to the stack.
            .next


; ----------------------------------------------------------------------
; 2>R [CORE EXT] 6.2.0340 "two-to-r"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( x1 x2 -- ) ( R:  -- x1 x2 )
;   Transfer cell pair x1 x2 to the return stack.  Semantically equivalent
;   to SWAP >R >R.

            .linkTo zeronotequals,0,3,'R',">2"
twotor POP     H           ; Pop x2 from the stack,
            XTHL                ; ..and then swap x1 with x2.;
            .rsPush H,L         ; Push x1 to the return stack.
            POP     H           ; Pop x2 from the stack again,
            .rsPush H,L         ; ..then push x2 to the return stack.
            .next


; ----------------------------------------------------------------------
; 2R> [CORE EXT] 6.2.0410 "two-r-from"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( -- x1 x2 ) ( R: x1 x2 -- )
;   Transfer cell pair x1 x2 from the return stack.  Semantically equivalent
;   to R> R> SWAP.

            .linkTo twotor,0,3,'>',"R2"
tworfrom .rsPop H,L          ; Pop x2 from the return stack
            PUSH    H           ; ..and push it to the stack (which is wrong).
            .rsPop H,L          ; Pop x1 from the return stack,
            XTHL                ; ..then swap x2 and x1 to fix things up,
            PUSH    H           ; ..and finally push x2 back onto the stack.
            .next


; ----------------------------------------------------------------------
; <> [CORE EXT] 6.2.0500 "not-equals" ( x1 x2 -- flag )
;
; flag is true if and only if x1 is not bit-for-bit the same as x2.

            .linkTo tworfrom,0,2,'>',"<"
notequals .saveDe
            POP     H           ; Pop x2.
            POP     D           ; Pop x1.
            PUSH    B           ; Save BC.
            MOV     B,D         ; Move x1
            MOV     C,E         ; ..to BC.
            .byte 08H                ; HL=HL-BC
            POP     B           ; Restore BC.
            JZ      _neqfalse   ; Jump if zero (equals) to where we push false.
            LXI     H,0FFFFH    ; Put true in HL.
            JMP     _neqdone    ; We're done.
_neqfalse LXI     H,0         ; Put false in HL.
_neqdone PUSH    H           ; Push the flag to the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; AGAIN [CORE EXT] 6.2.0700
;
; Compilation: ( C: dest -- )
;   Append the run-time semantics given below to the current definition,
;   resolving the backward reference dest.
;
; Run-time: ( -- )
;   Continue execution at the location specified by dest.  If no other
;   control flow words are used, any program code after AGAIN will not
;   be executed.
;
; ---
; : AGAIN   ['] branch COMPILE,  , ; IMMEDIATE

            .linkTo notequals,1,5,'N',"IAGA"
again JMP     enter
            .word   lit,branch,compilecomma,comma,exit


; ----------------------------------------------------------------------
; C" [CORE] 6.2.0855 "c-quote"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( "ccc<quote>" -- )
;   Parse ccc delimited by " (double-quote).  Append the run-time
;   semantics given below to the current definition.
;
; Run-time: ( -- c-addr )
;   Return c-addr, a counted string consisting of the characters ccc.
;   A program shall not alter the returned string.
;
; ---
; : C" ( "ccc<quote>" --)   ['] (C") COMPILE,
;   [CHAR] " PARSE  DUP C,  HERE OVER ALLOT SWAP CMOVE ;

            .linkTo again,1,2,022H,"C"
cquote JMP     enter
            .word   lit,pcquote,compilecomma,lit,022H,parse,dup,ccomma
            .word   here,over,allot,swap,cmove,exit


; ----------------------------------------------------------------------
; COMPILE, [CORE EXT] 6.2.0945 "compile-comma" ( xt -- )
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Execution: ( xt -- )
;   Append the execution semantics of the definition represented by xt to
;   the execution semantics of the current definition.  

            .linkTo cquote,0,8,02CH,"ELIPMOC"
compilecomma JMP    enter
            .word   comma,exit


; ----------------------------------------------------------------------
; FALSE [CORE EXT] 6.2.1485 ( -- false )
;
; Return a false flag.

            .linkTo compilecomma,0,5,'E',"SLAF"
false LXI     H,0
            PUSH    H
            .next


; ----------------------------------------------------------------------
; HEX [CORE EXT] 6.2.1660 ( -- )
;
; Set contents of BASE to sixteen.

            .linkTo false,0,3,'X',"EH"
hex JMP     enter
            .word   lit,16,base,store,exit


; ----------------------------------------------------------------------
; NIP [CORE EXT] 6.2.1930 ( x1 x2 -- x2 )
;
; Drop the first item below the top of stack.

            .linkTo hex,0,3,'P',"IN"
nip POP     H           ; Pop x2 into HL.
            POP     PSW         ; Pop x1 into A+PSW.
            PUSH    H           ; Push x2 back onto the stack.
            .next


; ----------------------------------------------------------------------
; PAD [CORE EXT] 6.2.2000 ( -- c-addr )
;
; c-addr is the address of a transient region that can be used to hold
; data for intermediate processing.
;
; ---
; : PAD ( -- c-addr)   HERE  PADOFFSET +  TASK-PAGE 'FIRSTTASK @ -  8 LSHIFT  + ;

            .linkTo nip,0,3,'D',"AP"
pad PUSH    D           ; Save DE.
            LHLD    dp          ; Get HERE into HL.
            LXI     D,padoffset ; Get the base PAD offset into DE
            DAD     D           ; ..and add the offset to HL.
            XCHG                ; Save HL in DE.
            LHLD    tickfirsttask;Get the address of the first task,
            MOV     A,H         ; ..move the page address into A,
            SUB     B           ; ..then calculate the task number (first-B).
            XCHG                ; Get HERE+PADOFFSET back into HL.
            MOV     D,A         ; Set DE to the
            MVI     E,0         ; ..task number * 256,
            DAD     D           ; ..and add that value to HL.
            XTHL                ; Swap PAD with IP,
            XCHG                ; ..and put IP back into DE.
            .next


; ----------------------------------------------------------------------
; PARSE [CORE EXT] 6.2.2008 ( char "ccc<char>" -- c-addr u )
;
; Parse ccc delimited by the delimiter char.
;
; c-addr is the address (within the input buffer) and u is the length of
; the parsed string.  If the parse area was empty, the resulting string
; has a zero length.
;
; ---
; : PARSE ( char "ccc<char>" -- c-addr u) FALSE SWAP (parse) ;

            .linkTo pad,0,5,'E',"SRAP"
parse JMP     enter
            .word   false,swap,pparse,exit


; ----------------------------------------------------------------------
; PICK [CORE EXT] 6.2.2030 ( xu ... x1 x0 u -- xu ... x1 x0 xu )
;
; Remove u.  Copy the xu to the top of the stack.  An ambiguous condition
; exists if there are less than u+2 items on the stack before PICK is
; executed.

            .linkTo parse,0,4,'K',"CIP"
pick POP     H           ; Get u into HL,
            DAD     H           ; ..double the value to get a cell offset,
            DAD     SP          ; ..then add SP to get the stack offset.
            MOV     A,M         ; Get the low byte of the stack value in A,
            INX     H           ; ..then increment to the high byte,
            MOV     H,M         ; ..get the high byte into H,
            MOV     L,A         ; ..move the low byte into L,
            PUSH    H           ; ..and push xu to the stack.
            .next


; ----------------------------------------------------------------------
; SOURCE-ID [CORE EXT] 6.2.2218 "source-i-d" ( -- 0 | -1 )
;
; Identifies the input source as follows:
;
;   =================================
;   SOURCE-ID   Input source
;   ---------------------------------
;    fileid     Text file "fileid"
;      -1       String (via EVALUATE)
;       0       User input device
;   =================================
;
; ---
; : SOURCE-ID ( -- 0 | -1)   ICB ICBSOURCEID + @ ;

            .linkTo pick,0,9,'D',"I-ECRUOS"
sourceid JMP     enter
            .word   icb,lit,icbsourceid,plus,fetch,exit


; ----------------------------------------------------------------------
; TIB [CORE EXT] 6.2.2290 "t-i-b" ( -- c-addr )
;
; c-addr is the address of the terminal input buffer.
;
; Note: This word is obsolescent and is included as a concession to
; existing implementations.

            .linkTo sourceid,0,3,'B',"IT"
tib LHLD    ticktib
            PUSH    H
            .next


; ----------------------------------------------------------------------
; TRUE [CORE EXT] 6.2.1485 ( -- true )
;
; Return a true flag.

            .linkTo tib,0,4,'E',"URT"
true LXI     H,0FFFFH
            PUSH    H
            .next


; ----------------------------------------------------------------------
; TUCK [CORE EXT] 6.2.2300 ( x1 x2 -- x2 x1 x2 )
;
; Copy the first (top) stack item below the second stack item.

            .linkTo true,0,4,'K',"CUT"
tuck .saveDe
            POP     D           ; Pop x2 into DE.
            POP     H           ; Pop x1 into HL.
            PUSH    D           ; Push x2 onto the stack.
            PUSH    H           ; Push x1 onto the stack.
            PUSH    D           ; Push x2 onto the stack again.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; WITHIN [CORE EXT] 6.2.2440 ( n1|u1 n2|u2 n3|u3 -- flag )
;
; Perform a comparison of a test value n1|u1 with a lower limit n2|u2 and
; an upper limit n3|u3, returning true if either (n2|u2 < n3|u3 and
; (n2|u2 <= n1|u1 and n1|u1 < n3|u3)) or (n2|u2 > n3|u3 and (n2|u2 <= n1|u1
; or n1|u1 < n3|u3)) is true, returning false otherwise.  An ambiguous
; condition exists if n1|u1, n2|u2, and n3|u3 are not all the same type.
;
; ---
; ; WITHIN ( n1|u1 n2|u2 n3|u3 -- flag)   OVER - >R - R>  U< ;

            .linkTo tuck,0,6,'N',"IHTIW"
within JMP     enter
            .word   over,minus,tor,minus,rfrom,ulessthan,exit


; ----------------------------------------------------------------------
; \ [CORE EXT] 6.2.2535 "backslash"
;
; Compilation:
;   Perform the execution semantics given below.
;
; Execution: ( "ccc<eol>"-- )
;   Parse and discard the remainder of the parse area.  \ is an immediate
;   word.
;
; ---
; : \   SOURCE NIP >IN ! ; IMMEDIATE

            .linkTo0 within,1,1,05CH
backslash JMP     enter
            .word   source,nip,toin,store,exit



; ======================================================================
; CORE EXT Words (implementation details)
; ======================================================================

; ----------------------------------------------------------------------
; (c") [MFORTH] "paren-c-quote-paren" ( -- c-addr )
;
; Runtime behavior of C": return c-addr.

            .linkTo backslash,0,4,029H,"\"c("
pcquote PUSH    D           ; Push string address onto the stack.
            .byte 0EDH                ; Read string count from instruction stream.
            MVI     H,0         ; Clear high byte, which is not part of count.
            INX     H           ; Increment HL to include the count byte.
            XCHG                ; IP to HL, count to DE.
            DAD     D           ; Add count to address to skip over string.
            XCHG                ; Put IP back in DE (pointing after string).
            .next


; ----------------------------------------------------------------------
; (parse) [MFORTH] "paren-parse-paren" ( flag char "ccc<char>" -- c-addr u )
;
; Parse ccc delimited by the delimiter char.  If flag is true then leading
; delimiters will be skipped and, if char is a space, then all control
; characters will be treated as delimiters as well.
;
; c-addr is the address (within the input buffer) and u is the length of
; the parsed string.  If the parse area was empty, the resulting string
; has a zero length.

            .linkTo pcquote,0,7,029H,"esrap("
last_coreext
pparse .saveDe
            .saveBc

            ; Get ICBLINEEND and ICBLINESTART on the stack.
            LHLD    tickicb     ; Get the current ICB into HL,
            XCHG                ; ..then move it to DE,
            .byte 0EDH                ; ..fetch ICBLINEEND,
            PUSH    H           ; ..and push it to the stack.
            INX     D           ; Increment to
            INX     D           ; ..ICBLINESTART,
            .byte 0EDH                ; ..fetch ICBLINESTART,
            PUSH    H           ; ..and push it to the stack.
            
            ; Get >IN and add that to ICBLINESTART.
            INX     D           ; Increment
            INX     D           ; ..past SOURCE-ID
            INX     D           ; ..to
            INX     D           ; ..ICBTOIN,
            .byte 0EDH                ; ..and fetch ICBTOIN.
            POP     B           ; Pop ICBLINESTART
            DAD     B           ; ..and add it to ICBTOIN to get srcpos.
            MOV     D,H         ; Make a copy of srcpos
            MOV     E,L         ; ..in DE.
            
            ; Calculate srcrem.
            XTHL                ; Swap srcpos and ICBLINEEND.
            POP     B           ; Pop srcpos into BC,
            .byte 08H                ; ..then subtract srcpos from ICBLINEEND.
            MOV     B,H         ; Move srcrem into B
            MOV     C,L         ; ..and C.
            XCHG                ; Get ICBLINESTART into HL as srcpos.
            
            ; Get the delimiter in D, flag in E, and push srcpos (aka c-addr).
            POP     D           ; Pop char into E,
            MOV     A,E         ; ..temporarily move to A,
            POP     D           ; ..pop flag into E,
            MOV     D,A         ; ..then move the delimiter back into D.
            PUSH    H           ; Push the start position to the stack,
            PUSH    H           ; ..then push c-addr to the stack.

            ; Skip delimiters if required.
            ; D=delim E=flag HL=srcpos BC=srcrem  Stack: startpos c-addr
            MOV     A,E         ; Move the flag into A,
            ORA     A           ; ..see if the flag is zero,
            JZ      _pparseloop ; ..and skip ahead to the loop if so.
_pparseskip MOV     A,B         ; See if we have reached
            ORA     C           ; ..the end of src
            JZ      _pparseskip2; ..and exit the loop if so.
            MOV     A,M         ; Get the next character at srcpos
            CMP     D           ; ..and see if it is the same as delim;
            JZ      _pparseskip1; ..keep skipping if so.
            ANA     E           ; Not a match; but is our flag true?
            JZ      _pparseskip2; ..if not, just start looping.
            ANI     11100000b   ; Flag is true; is A a control char?
            JNZ     _pparseskip2; ..if not, just start looping,
            MOV     A,D         ; ..otherwise move delim to A,
            CPI     020H        ; ..and see if the result is a space;
            JNZ      _pparseskip2;..start looping if not, otherwise continue.
_pparseskip1 INX    H           ; Increment srcpos,
            DCX     B           ; ..decrement srcrem,
            JMP     _pparseskip ; ..and continue skipping.
_pparseskip2 INX    SP          ; Remove the old c-addr
            INX     SP          ; ..from the stack
            PUSH    H           ; ..and replace it with the post-delim c-addr.

            ; Find the end of the delimited text.
            ; D=delim E=flag HL=srcpos BC=srcrem  Stack: startpos c-addr
_pparseloop MOV     A,B         ; See if we have reached
            ORA     C           ; ..the end of src
            JZ      _pparsedone ; ..and exit the loop if so.
            MOV     A,M         ; Get the next character at srcpos
            CMP     D           ; ..and see if it is the same as delim;
            JZ      _pparsedone ; ..we're done if so.
            ANA     E           ; Not a match; but is our flag true?
            JZ      _pparseloop1; ..if not just keep looping.
            ANI     11100000b   ; Flag is true; is A a control char?
            JNZ     _pparseloop1; ..if not, just keep looping,
            MOV     A,D         ; ..otherwise move delim to A,
            CPI     020H        ; ..and see if the result is a space;
            JZ      _pparsedone ; ..stop looping if so, otherwise continue.
_pparseloop1 INX    H           ; Increment srcpos,
            DCX     B           ; ..decrement srcrem,
            JMP     _pparseloop ; ..and continue looping.

            ; Update >IN and calculate the length of the parsed text.
            ; HL=endpos  Stack: startpos c-addr
_pparsedone MOV     D,B         ; Move srcrem to D
            MOV     E,C         ; ..and E.
            SHLD    holdh       ; Save endpos for later use.
            POP     H           ; Pop c-addr from the stack,
            POP     B           ; ..pop the start position into BC.
            PUSH    H           ; ..then put c-addr back onto the stack,
            LHLD    holdh       ; ..and restore endpos.
            .byte 08H                ; Get the total number of bytes seen into HL.
            MOV     A,D         ; See if we exhaused srcrem, in which case we do
            ORA     E           ; ..not need to skip the (missing) final delim.
            JZ      _pparsedone1; No delim to skip if we hit EOL,
            INX     H           ; ..otherwise increment length to include delim.
_pparsedone1 MOV    B,H         ; Move the total length to B
            MOV     C,L         ; ..and C.
            LHLD    tickicb     ; Get the current ICB into HL,
            INX     H           ; ..skip
            INX     H           ; ..ahead
            INX     H           ; ..to
            INX     H           ; ..the
            INX     H           ; ..>IN
            INX     H           ; ..offset,
            XCHG                ; ..move the offset to DE,
            .byte 0EDH                ; ..load the current value of >IN into HL,
            DAD     B           ; ..and add the parsed length to >IN.
            .byte 0D9H                ; Save the new >IN.
            
            LHLD    holdh       ; Restore endpos again,
            POP     B           ; ..get c-addr from the stack,
            PUSH    B           ; ..put a copy of c-addr back onto the stack,
            .byte 08H                ; ..then calculate the parsed length,
            PUSH    H           ; ..and push that length onto the stack.
            
            .restoreBc
            .restoreDe
            .next
