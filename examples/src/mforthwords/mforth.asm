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
; MFORTH Words
; ======================================================================

; ----------------------------------------------------------------------
; -ROT [MFORTH] "dash-rote" ( x1 x2 x3 -- x3 x1 x2 )
;
; Reverse-rotate the top three stack entries.

            .linkTo link_mforth,0,4,'T',"OR-"
dashrot .saveDe
            POP     H           ; Pop x3 into HL.
            POP     D           ; Pop x2 into DE.
            XTHL                ; Swap TOS (x1) with HL (x3).
            PUSH    H           ; Push x1 back onto the stack.
            PUSH    D           ; Push x2 back onto the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; .VER [MFORTH] "dot-ver" ( -- )
;
; Display the MFORTH version as a string of 16 characters ("MFORTH 1.0.0000 ").
; The space in the 16th position will be replaced with a "P" if this is a
; build that includes the profiler.
;
; ---
; : .VER ( --)
;   ." MFORTH v"
;   MFORTH_MAJOR [CHAR] 0 + EMIT  [CHAR] . EMIT
;   MFORTH_MINOR [CHAR] 0 + EMIT  [CHAR] . EMIT
;   BASE @  HEX  MFORTH_CHANGE 0 <# # # # # #> TYPE  BASE !
;   [ PROFILER ] [IF] [CHAR] P EMIT [ELSE] SPACE [THEN] ;

            .linkTo dashrot,0,4,'R',"EV."
dotver JMP     enter
            .word   psquote,7
            .byte   "MFORTH "
            .word   type
            .word   lit,mforth_major,lit,'0',plus,emit,lit,'.',emit
            .word   lit,mforth_minor,lit,'0',plus,emit,lit,'.',emit
            .word   base,fetch,hex,lit,mforth_change,zero
            .word   lessnumsign,numsign,numsign,numsign,numsign,numsigngrtr
            .word   type,base,store
.ifdef profiler
            .word   lit,'P',emit
.else
            .word   space
.endif
            .word   exit


; ----------------------------------------------------------------------
; 2NIP [MFORTH] "two-nip" ( x1 x2 x3 x4 -- x3 x4 )
;
; Drop the first cell pair below the cell pair at the top of the stock.

            .linkTo dotver,0,4,'P',"IN2"
twonip .saveDe
            POP     H           ; Pop x4.
            POP     D           ; Pop x3.
            POP     PSW         ; Pop x2.
            POP     PSW         ; Pop x1.
            PUSH    D           ; Push x3 back onto the stack.
            PUSH    H           ; Push x4 back onto the stack.
            .restoreDe
            .next


; ----------------------------------------------------------------------
; 8* [MFORTH] "eight-star" ( x1 -- x2 )
;
; x2 is the result of shifting x1 three bits toward the most-significant
; bit, filling the vacated least-significant bit with zero.

            .linkTo twonip,0,2,'*',"8"
eightstar POP     H           ; Pop x1.
            DAD     H           ; Shift
            DAD     H           ; ..x1
            DAD     H           ; ..three times.
            PUSH    H           ; Push the result onto the stack.
            .next


; ----------------------------------------------------------------------
; GET-XY [MFORTH] "get-x-y" ( -- u1 u2 )
;
; Return the current cursor position (column u1, row u2) from the
; current input device, the upper left corner of which is column zero,
; row zero.

            .linkTo eightstar,0,6,'Y',"X-TEG"
getxy MVI     H,0         ; Initialize H with zero.
            LDA     0F63AH      ; Get the column into A,
            DCR     A           ; ..subtract one,
            MOV     L,A         ; ..move it to L,
            PUSH    H           ; ..and push the result to the stack.
            LDA     0F639H      ; Get the row into A,
            DCR     A           ; ..subtract one,
            MOV     L,A         ; ..move it to L,
            PUSH    H           ; ..and push the result to the stack.
            .next


; ----------------------------------------------------------------------
; COLD [MFORTH] ( i*x -- ) ( R: j*x -- )
;
; Clear the screen, display our copyright/help message, (re)insert our ROM
; trigger file, initialize our File Control Blocks, then jump to ABORT (which
; clears the stack and calls QUIT, which clears the return stack and enters
; the infinite text interpreter loop).
;
; ---
; : COLD ( i*x --; R: j*x --)
;   PAGE  .VER 2 SPACES ." (C)Michael Alyn Miller"
;   INS-ROMTRIG INIT-FCBS ABORT ;
;
; ABORT should never return, but we HALT anyway just in case someone
; messes with the return stack.

            .linkTo getxy,0,4,'D',"LOC"
cold JMP     enter
            .word   page,dotver,lit,2,spaces
            .word   psquote,22
            .byte   "(C)Michael Alyn Miller"
            .word   type,insromtrig,initfcbs,abort
            .word   halt


; ----------------------------------------------------------------------
; COPY-LINE [MFORTH] ( addr1 addr2 u1 -- u2 u3 )
;
; If u1 is greater than zero, copy the contents of u1 consecutive address
; units at addr1 to the u1 consecutive address units at addr2, stopping if
; a CRLF sequence is found or end-of-file is reached before u1 address units
; have been copied.  After COPY-LINE completes, the u2 consecutive address
; units at addr2 contain exactly what the u2 consecutive address units at
; addr1 contained before the move.  u2 is the number of address units that
; were copied.  u3 is the number of address units that should be skipped
; in addr1 before the next call to COPY-LINE.  u3 will normally be u2+2 if
; CRLF was reached before u1 or EOF was reached.  Note that EOF is not
; included in u3, only CRLF is included in u3.
;
; ---
; : COPY-LINE ( addr1 addr2 u1 -- u2 u3)
;   ROT SWAP 2>B DUP ( addr2 addr2') FORB
;   B@ 26 = ?ENDB
;   B@ 13 = B# 1 > AND IF B 1+ C@ 10 = IF SWAP - DUP 1+ 1+ EXIT THEN THEN
;   B@ OVER C! 1+ NEXTB
;   SWAP - DUP ;

            .linkTo cold,0,9,'E',"NIL-YPOC"
copyline JMP     enter
            .word   rot,swap,twotob,dup
_copyline1 .word   bques,zbranch,_copyline3
            .word   bfetch,lit,26,equals,invert,zbranch,_copyline3
            .word   bfetch,lit,13,equals,bnumber,one,greaterthan,and
            .word       zbranch,_copyline2
            .word   B,oneplus,cfetch,lit,10,equals,zbranch,_copyline2
            .word   swap,minus,dup,oneplus,oneplus,exit
_copyline2 .word   bfetch,over,cstore,oneplus,bplus,branch,_copyline1
_copyline3 .word   swap,minus,dup,exit


; ----------------------------------------------------------------------
; HALT [MFORTH] ( -- )
;
; Halt the processor.

            .linkTo copyline,0,4,'T',"LAH"
halt HLT                 ; Halt the processor.
            .next


; ----------------------------------------------------------------------
; INITRP [MFORTH] "init-r-p" ( -- ) ( R:  i*x -- )
;
; Empty the return stack.

            .linkTo halt,0,6,'P',"RTINI"
initrp MVI     C,07FH
            .next


; ----------------------------------------------------------------------
; INS-ROMTRIG [MFORTH] ( -- )
;
; Insert our ROM Trigger file, replacing an existing ROM Trigger file with
; our own if one is found.
;
; ---
; : INS-ROMTRIG ( --)
;   FIND-ROMTRIG  DUP 0= IF FREDIR THEN  >B
;   240 B!+  255 B!+ 255 B!+  S" MFORTH" B SWAP  DUP B + >B  MOVE
;   BL B!+ BL B!+ ;
; : FIND-ROMTRIG ( -- 0 | addr)
;   [ USRDIR 11 - ] LITERAL  BEGIN NXTDIR DUP WHILE
;       DUP C@ 16 AND IF EXIT THEN REPEAT ;

            .linkTo initrp,0,11,'G',"IRTMOR-SNI"
insromtrig JMP     enter
            .word   findromtrig,dup,zeroequals,zbranch,_insromtrig1,fredir
_insromtrig1 .word  tob,lit,240,bstoreplus,lit,255,bstoreplus,lit,255,bstoreplus
            .word   psquote,6
            .byte   "MFORTH"
            .word   B,swap,dup,B,plus,tob,move,bl,bstoreplus,bl,bstoreplus
            .word   exit

            .linkTo insromtrig,0,12,'G',"IRTMOR-DNIF"
findromtrig JMP     enter
            .word   lit,0F9BAH-11
_findromtrig1 .word nxtdir,dup,zbranch,_findromtrig3
            .word   dup,cfetch,lit,16,and,zbranch,_findromtrig2
            .word   exit
_findromtrig2 .word branch,_findromtrig1
_findromtrig3 .word exit

            .linkTo findromtrig,0,6,'R',"IDTXN"
nxtdir POP     H           ; Get the entry prior to the start position.
            CALL    stdcall     ; Call the
            .word   020D5H      ; .."NXTDIR" routine.
            JZ      _nxtdirzero ; Jump if zero to where we push zero/not found.
            JMP     _nxtdirfound; We're done.
_nxtdirzero LXI     H,0         ; Put zero in HL.
_nxtdirfound PUSH   H           ; Push the location (or zero) to the stack.
            .next

            .linkTo nxtdir,0,6,'R',"IDERF"
fredir PUSH    B           ; Save BC (corrupted by FREDIR).
            CALL    stdcall     ; Call the
            .word   020ECH      ; .."FREDIR" routine.
            POP     B           ; Restore BC.
            PUSH    H           ; Push the location of the free entry.
            .next



; ----------------------------------------------------------------------
; LCD [MFORTH] "l-c-d" ( -- )
;
; Select the LCD display as the output device.

            .linkTo fredir,0,3,'D',"CL"
lcd CALL    stdcall     ; Call the
            .word   04B92H      ; .."Reinitialize back to LCD" routine.
            .next


; ----------------------------------------------------------------------
; PARSE-WORD [MFORTH] ( "<spaces>name<space>" -- c-addr u )
;
; Skip leading spaces and parse name delimited by a space. c-addr is the
; address within the input buffer and u is the length of the selected
; string. If the parse area is empty, the resulting string has a zero length. 
;
; ---
; : PARSE-WORD ( "<spaces>name<space>" -- c-addr u) TRUE BL (parse) ;

            .linkTo lcd,0,10,'D',"ROW-ESRAP"
parseword JMP     enter
            .word   true,bl,pparse,exit


; ----------------------------------------------------------------------
; PRN [MFORTH] "p-r-n" ( -- )
;
; Select the printer as the output device.

            .linkTo parseword,0,3,'N',"RP"
prn JMP     enter
            .word   one,lit,0F675H,store,exit


; ----------------------------------------------------------------------
; SP [MFORTH] ( -- a-addr )
;
; a-addr is the value of the stack pointer before a-addr was placed on
; the stack.

            .linkTo prn,0,2,'P',"S"
sp LXI     H,0
            DAD     SP
            PUSH    H
            .next


; ----------------------------------------------------------------------
; SP! [MFORTH] ( i*x a-addr -- )
;
; Set the stack pointer to a-addr.

            .linkTo SP,0,3,'!',"PS"
spstore POP     H
            SPHL
            .next


; ----------------------------------------------------------------------
; TICKS [MFORTH] ( -- ud )
;
; ud is the number of ticks that have elapsed since MFORTH was started.

            .linkTo spstore,0,5,'S',"KCIT"
ticks DI
            LHLD    tickticks
            PUSH    H
            LHLD    tickticks+2
            EI
            PUSH    H
            .next


; ----------------------------------------------------------------------
; TICKS>MS [MFORTH] "ticks-to-m-s" ( ud1 -- ud2 )
;
; Convert a tick count (ud1) to a value in milliseconds (ud2).
;
; ---
; : TICKS>MS ( ud1 -- ud2)   D2* D2* ;

            .linkTo ticks,0,8,'S',"M>SKCIT"
tickstoms JMP     enter
            .word   dtwostar,dtwostar,exit


; ----------------------------------------------------------------------
; TIMED-EXECUTE [MFORTH] ( i*x xt -- j*x ud )
;
; Execute the given xt and return the approximate number of milliseconds
; required for execution.
;
; ---
; : TIMED-EXECUTE ( i*x xt -- j*x ud)
;   TICKS 2>R  EXECUTE  TICKS 2R>  D- ;

            .linkTo tickstoms,0,13,'E',"TUCEXE-DEMIT"
timedexecute JMP    enter
            .word   ticks,twotor,execute,ticks,tworfrom,dminus,exit


; ----------------------------------------------------------------------
; VOCABULARY [MFORTH] ( "<spaces>name" -- )
;
; Skip leading space delimiters.  Parse name delimited by a space.  Create
; a definition for name with the execution semantics defined below.
;
; name is referred to as a "word list".
;
; name Execution: ( -- )
;   Replace the first word list in the search order with name.
;
; ---
; : VOCABULARY ( "<spaces>name" -- )
;   CREATE WORDLIST DOES> SOESTART ! ;

            .linkTo timedexecute,0,10,'Y',"RALUBACOV"
vocabulary JMP     enter
            .word   create,lit,-cfasz,allot,lit,195,ccomma,lit,pvocabulary,comma
            .word   wordlist
            .word   exit
pvocabulary CALL    dodoes
            .word   lit,soestart,store,exit


; ----------------------------------------------------------------------
; [HEX] [MFORTH] "bracket-hex"
;
; Interpretation:
;   Interpretation semantics for this word are undefined.
;
; Compilation: ( "<spaces>hexnum" -- )
;   Skip leading space delimiters.  Parse hexnum, a base 16 number
;   delimited by a space.  Append the run-time semantics given below to
;   the current definition.
;
; Run-time: ( -- u )
;   Place u, the value of hexnum, on the stack.
;
; ---
; : [HEX] ( "<spaces>name" -- u)
;   BASE @  HEX PARSE-WORD  ( savedbase ca u)
;   NUMBER? IF ['] LIT COMPILE, , BASE ! EXIT THEN
;   ABORT" Not a hex number" ; IMMEDIATE

            .linkTo vocabulary,1,5,']',"XEH["
last_mforth
brackethex JMP     enter
            .word   base,fetch,hex,parseword
            .word   numberq,zbranch,_brackethex1
            .word   lit,lit,compilecomma,comma,base,store,exit
_brackethex1 .word  psquote,16
            .byte   "Not a hex number"
            .word   type,abort
