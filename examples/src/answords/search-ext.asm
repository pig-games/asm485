; Copyright (c) 2011, Michael Alyn Miller <malyn@strangeGizmo.com>.
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
; SEARCH-ORDER-EXT Words
; ======================================================================

; ----------------------------------------------------------------------
; ALSO [SEARCH EXT] 16.6.2.0715 ( -- )
;
; Transform the search order consisting of widn, ... wid2, wid1 (where
; wid1 is searched first) into widn, ... wid2, wid1, wid1.  An ambiguous
; condition exists if there are too many word lists in the search order.
;
; ---
; : ALSO ( -- )   SOESTART  DUP CELL+  #SOES CELLS  MOVE ;

            .linkTo link_searchext,0,4,'O',"SLA"
also JMP     enter
            .word   lit,soestart,dup,cellplus,numsoes,cells,move,exit


; ----------------------------------------------------------------------
; FORTH [SEARCH EXT] 16.6.2.1590 ( -- )
;
; Transform the search order consisting of widn, ... wid2, wid1 (where
; wid1 is searched first) into widn, ... wid2, widFORTH-WORDLIST.
;
; ---
; : FORTH ( -- )   FORTH-WORDLIST SOESTART ! ;

            .linkTo also,0,5,'H',"TROF"
forth JMP     enter
            .word   forthwordlist,lit,soestart,store
            .word   exit


; ----------------------------------------------------------------------
; ONLY [SEARCH EXT] 16.6.2.1965 ( -- )
;
; Set the search order to the implementation-defined minimum search
; order.  The minimum search order shall include the words
; FORTH-WORDLIST and SET-ORDER.
;
; ---
; : ONLY ( -- )   SOESTART [ MAXSOES CELLS ] 0 FILL  FORTH ;

            .linkTo forth,0,4,'Y',"LNO"
only JMP     enter
            .word   lit,soestart,lit,maxsoes,cells,zero,fill,forth
            .word   exit


; ----------------------------------------------------------------------
; ORDER [SEARCH EXT] 16.6.2.1985 ( -- )
;
; Display the word lists in the search order in their search order
; sequence, from first searched to last searched.  Also display the word
; list into which new definitions will be placed.  The display format is
; implementation dependent.
;
; ORDER may be implemented using pictured numeric output words.
; Consequently, its use may corrupt the transient region identified by
; #>.
;
; ---
; : ORDER ( -- )
;   GET-ORDER 0 DO HEXCELL SPACE LOOP
;   [CHAR] [ EMIT GET-CURRENT HEXCELL [CHAR] ] EMIT ;

            .linkTo only,0,5,'R',"EDRO"
order JMP     enter
            .word   getorder,zero,pdo
_order1 .word   hexcell,space,ploop,_order1
_order2 .word   lit,'[',emit,getcurrent,hexcell,lit,']',emit
            .word   exit


; ----------------------------------------------------------------------
; PREVIOUS [SEARCH EXT] 16.6.2.2037 ( -- )
;
; Transform the search order consisting of widn, ... wid2, wid1 (where
; wid1 is searched first) into widn, ... wid2.  An ambiguous condition
; exists if the search order was empty before PREVIOUS was executed.
;
; ---
; : PREVIOUS ( -- )
;   SOESTART  DUP CELL+  SWAP  #SOES 1- CELLS  MOVE
;   0  SOESTART  #SOES 1- CELLS  +  ! ;

            .linkTo order,0,8,'S',"UOIVERP"
last_searchext
previous JMP     enter
            .word   lit,soestart,dup,cellplus,swap
            .word   numsoes,oneminus,cells,move
            .word   zero,lit,soestart,numsoes,oneminus,cells,plus,store
            .word   exit
