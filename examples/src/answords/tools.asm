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
; TOOLS Words
; ======================================================================

; ----------------------------------------------------------------------
; .S [TOOLS] 15.6.1.0220 "dot-s" ( -- )
;
; Copy and display the values currently on the data stack. The format of
; the display is implementation-dependent.
;
; .S may be implemented using pictured numeric output words.  Consequently,
; its use may corrupt the transient region identified by #>.
;
; ---
; .S ( --)   DEPTH BEGIN ?DUP WHILE DUP PICK . 1- REPEAT ;

            .linkTo link_tools,0,2,'S',"."
dots JMP     enter
            .word   depth
_dots1 .word   qdup,zbranch,_dots2,dup,pick,dot,oneminus,branch,_dots1
_dots2 .word   exit


; ----------------------------------------------------------------------
; DUMP [TOOLS] 15.6.1.1280 ( addr u -- )
;
; Display the contents of u consecutive addresses starting at addr. The
; format of the display is implementation dependent. 
;
; DUMP may be implemented using pictured numeric output words. Consequently,
; its use may corrupt the transient region identified by #>.
;
; ---
; MFORTH Output Format (screen represented by the box):
; +----------------------------------------+
; |0000  00 01 02 03 04 05 06 07  Hello th |
; |0008  08 09 0a 0b 0c 0d        ere!..   |
; |...                                     |
; +----------------------------------------+
;
; : HEXCELL ( u --)  BASE @ SWAP HEX 0 <# # # # # #> TYPE BASE ! ;
; : HEXCHAR ( c --)  BASE @ SWAP HEX 0 <# # # #> TYPE BASE ! ;
; : EMITVALID ( c --)  DUP 32 < OVER 127 = OR  [CHAR] . AND OR  EMIT ;
; : DUMPLINE ( addr u --)
;   OVER HEXCELL 2 SPACES                                       -- address
;   DUP 0 DO OVER I + C@ HEXCHAR SPACE LOOP                     -- hex vals
;   8 OVER - 3 * SPACES  SPACE                                  -- padding
;   0 DO DUP I + C@ EMITVALID LOOP  DROP;
; : DUMP ( addr u --)
;   DUP 0 ?DO  CR  OVER I +  OVER I - 8 MIN  DUMPLINE  8 +LOOP  2DROP ;

            .linkTo dots,0,4,'P',"MUD"
dump JMP     enter
            .word   dup,zero,pqdo,_dump2
_dump1 .word   cr,over,i,plus,over,i,minus,lit,8,min,dumpline
            .word       lit,8,pplusloop,_dump1
_dump2 .word   twodrop,exit
hexcell JMP     enter
            .word   base,fetch,swap,hex,zero
            .word   lessnumsign,numsign,numsign,numsign,numsign,numsigngrtr,type
            .word   base,store,exit
hexchar JMP     enter
            .word   base,fetch,swap,hex,zero
            .word   lessnumsign,numsign,numsign,numsigngrtr,type
            .word   base,store,exit
emitvalid JMP     enter
            .word   dup,lit,32,lessthan,over,lit,127,equals,or
            .word   lit,'.',and,or,emit,exit
dumpline JMP     enter
            .word   over,hexcell,lit,2,spaces
            .word   dup,zero,pdo
_dumpline1 .word   over,i,plus,cfetch,hexchar,space,ploop,_dumpline1
            .word   lit,8,over,minus,lit,3,star,spaces,space
            .word   zero,pdo
_dumpline2 .word   dup,i,plus,cfetch,emitvalid,ploop,_dumpline2
            .word   drop,exit


; ----------------------------------------------------------------------
; WORDS [TOOLS] 15.6.1.2465 ( -- )
;
; List the definition names in the first word list of the search order.
; The format of the display is implementation-dependent.
;
; WORDS may be implemented using pictured numeric output words.
; Consequently, its use may corrupt the transient region identified by #>.
;
; ---
; : WORDS ( -- )
;   LATEST @  BEGIN  DUP HIDDEN? 0=  IF SPACE DUP .NAME THEN
;   NFA>LFA @  DUP 0= UNTIL DROP ;

            .linkTo dump,0,5,'S',"DROW"
words JMP     enter
            .word   latest,fetch
_words1 .word   dup,hiddenq,zeroequals,zbranch,_words2
            .word   space,dup,dotname
_words2 .word   nfatolfa,fetch,dup,zeroequals,zbranch,_words1
            .word   drop,exit



; ======================================================================
; TOOLS Words (implementation details)
; ======================================================================

; ----------------------------------------------------------------------
; .NAME [MFORTH] "dot-name" ( nfa-addr -- )
;
; Display the name of the dictionary entry pointed to by nfa-addr (which
; points to the length field).
;
; ---
; : .NAME ( nfa-addr -- )
;   BEGIN  1- DUP C@  DUP 127 AND EMIT  128 AND UNTIL DROP ;

            .linkTo words,0,5,'E',"MAN."
last_tools
dotname JMP     enter
_dotname1 .word   oneminus,dup,cfetch,dup,lit,127,and,emit
            .word       lit,128,and,zbranch,_dotname1
            .word   drop,exit


