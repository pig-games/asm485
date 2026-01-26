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
; SEARCH-ORDER Words
; ======================================================================

; ----------------------------------------------------------------------
; DEFINITIONS [SEARCH] 16.6.1.1180 ( -- )
;
; Make the compilation word list the same as the first word list in the
; search order.  Specifies that the names of subsequent definitions will
; be placed in the compilation word list.  Subsequent changes in the
; search order will not affect the compilation word list.
;
; ---
; : DEFINITIONS ( -- )   CONTEXT @ SET-CURRENT ;

            .linkTo link_search,0,11,'S',"NOITINIFED"
definitions JMP     enter
            .word   context,fetch,setcurrent,exit


; ----------------------------------------------------------------------
; FORTH-WORDLIST [SEARCH] 16.6.1.1595 ( -- wid )
;
; Return wid, the identifier of the word list that includes all standard
; words provided by the implementation.  This word list is initially the
; compilation word list and is part of the initial search order.

            .linkTo definitions,0,14,'T',"SILDROW-HTROF"
forthwordlist JMP   enter
            .word   lit,forthwl,exit


; ----------------------------------------------------------------------
; GET-CURRENT [SEARCH] 16.6.1.1643 ( -- wid )
;
; Return wid, the identifier of the compilation word list.

            .linkTo forthwordlist,0,11,'T',"NERRUC-TEG"
getcurrent JMP     enter
            .word   current,fetch,exit


; ----------------------------------------------------------------------
; GET-ORDER [SEARCH] 16.6.1.1647 ( -- widn ... wid1 n )
;
; Returns the number of word lists n in the search order and the word
; list identifiers widn ... wid1 identifying these word lists.  wid1
; identifies the word list that is searched first, and widn the word
; list that is searched last.  The search order is unaffected.
;
; ---
; : GET-ORDER ( -- widn ... wid1 n)
;   0 #SOES 1- DO  SOESTART I CELLS + @  -1 +LOOP  #SOES ;

            .linkTo getcurrent,0,9,'R',"EDRO-TEG"
getorder JMP     enter
            .word   zero,numsoes,oneminus,pdo
_getorder1 .word   lit,soestart,i,cells,plus,fetch,lit,-1,pplusloop,_getorder1
            .word   numsoes
            .word   exit


; ----------------------------------------------------------------------
; SEARCH-WORDLIST [SEARCH] 16.1.2192 ( c-addr u wid -- 0 | xt 1 | xt -1 )
;
; Find the definition identified by the string c-addr u in the word list
; identified by wid.  If the definition is not found, return zero.  If
; the definition is found, return its execution token xt and one (1) if
; the definition is immediate, minus-one (-1) otherwise.
;
; ---
; This word traverses the dictionary's linked list until the traversal
; enters ROM.  At that point (FIND) stops using the linked list and tries
; to locate the word using the perfect hash table generated at build
; time.  This only happens if wid points to the FORTH word list, which
; is tracked by B (FORTH=0; other=-1).  The _phash subroutine generates
; two hash values, H and L.  The target word, if it exists in ROM, will
; be found at one of two locations: HL or LH.  HL is the more likely
; location and is searched first.  C maintains the state of the search
; location.  -1 indicates that the search should use HL, 0 indicates
; that the search should use LH, and 1 indicates that the search failed.

            .linkTo getorder,0,15,'T',"SILDROW-HCRAES"
searchwordlist .saveDe
            .saveBc
            POP     D           ; Get wid from the stack,
            MOV     B,D         ; ..copy wid into B
            MOV     C,E         ; ..and C,
            LXI     H,forthwl   ; ..get the FORTH wid in HL,
            .byte 08H                ; ..then compare wid to the FORTH wid;
            JZ      _swlforth   ; ..jump to where we clear B if FORTH,
            MVI     B,-1        ; ..otherwise set B to -1
            JMP     _swllatest  ; ..and load LATEST.
_swlforth MVI     B,0         ; FORTH wid, so clear B.
_swllatest .byte 0EDH                ; Get the latest word in wid
            XCHG                ; ..and put that value in DE.
            MVI     C,-1        ; Initialize our phash flag to -1.
            POP     H           ; Pop the length of the string
            SHLD    holdd       ; ..and cache the value.
            POP     H           ; Pop the string pointer
            SHLD    holdh       ; ..and cache the value.
_swlagain
.ifdef phash
            MOV     A,D         ; See if we are still in RAM (the
            ANI     80H         ; ..high bit of the addr is not zero) -- or
            ORA     B           ; ..we are not in the FORTH word list -- and
            JNZ     _swlagain1  ; ..keep traversing the linked list if so.
_swlphash PUSH    H           ; Save the string pointer on the stack,
            LDA     holdd       ; ..get the string length into A,
            CALL    _phash      ; ..then hash the string.
            MOV     A,C         ; Move our phash flag to A,
            ORA     A           ; ..then check the state of the flag:
            JM      _swlphashh1 ; ..use H1 if the value is negative;
            JZ      _swlphashh2 ; ..use H2 if the value is zero;
            POP     H           ; ..otherwise no match, pop the counted string
            JMP     _swlfail    ; ..and fail.
_swlphashh2 MOV     A,L         ; Move H2 to A,
            MOV     L,H         ; ..move H1 to L,
            JMP     _swlphash1  ; ..then continue.
_swlphashh1 MOV     A,H         ; Move H1 to A
_swlphash1 ANI     phashmask   ; ..and mask off the high bits of H1.
            MOV     H,A         ; Get the masked off bits of H1 back into H.
            DAD     H           ; HL=HL<<1 to convert from hash to cell offset.
            MOV     A,H         ; Move the high byte of the offset to A,
            ADI     phashtab >> 8 ; ..add the high byte of PHASHTAB to A,
            MOV     H,A         ; ..and then put the PHASHTAB address into H.
            MOV     E,M         ; Get the low byte of the hash cell in E,
            INX     H           ; ..increment to the high byte,
            MOV     D,M         ; ..then get the low byte into D.
            POP     H           ; Restore the string pointer.
            INR     C           ; Increment our phash flag.
            MOV     A,D         ; Move D to A,
            ORA     E           ; ..then OR A and E to see if the cell is zero;
            JZ      _swlphash   ; ..try to phash again if so.
.endif
_swlagain1 LDAX    D           ; Get the name length into A.
            ANI     01111111b   ; Strip the immediate bit.
            LXI     H,holdd     ; Point HL at the string length,
            CMP     M           ; ..then compare the two lengths+smudge bits.
            JNZ     _swlnextword;Jump if not zero (not equal) to the next word.
            PUSH    D           ; Save DE since we are about to scan through it.
            DCX     D           ; Go to the first dictionary char (prev byte).
            LHLD    holdh       ; Point HL at the first string character.
_swlnextchar LDAX   D           ; Get the next dictionary value into A.
            ANI     01111111b   ; Strip the end-of-name bit.
            CMP     M           ; Compare the two characters.
            JZ      _swlmatchchar;Jump if zero (equal) to match.
            XRI     00100000b   ; Try switching the case
            CMP     M           ; ..and then repeating the match.
            JNZ     _swlnextwordde;.Not a match if not zero (not equal).
            ORI     00100000b   ; Only a match if A-Z/a-z.  Force to lower,
            CPI     'a'         ; ..then see if less than 'a'.
            JM      _swlnextwordde;.If so, this is not a match.
            CPI     'z'+1       ; If greater than 'z'+1,
            JP      _swlnextwordde;.then this is also not a match.
_swlmatchchar LDAX  D           ; The strings are a match if this is the last
            ANI     10000000b   ; ..character in the name (high bit set).
            JNZ     _swlmatch   ; We're done if this is a match.
            DCX     D           ; Go to the next dictionary char (prev byte).
            INX     H           ; Go to the next string character.
            JMP     _swlnextchar;Evaluate the next character.
_swlmatch POP     D           ; Restore DE (which is now pointing at a char)
            LDAX    D           ; Get the flags into A
            ANI     10000000b   ; ..and focus on just the immediate flag.
            .inxNfaToCfa D      ; Skip ahead to the CFA (xt)
            PUSH    D           ; ..and push xt to the stack.
            JNZ     _swlimm     ; Immediate gets a 1 pushed to the stack,
            LXI     H,0FFFFH    ; ..non-immediate gets a -1
            PUSH    H           ; ..pushed to the stack.
            JMP     _swldone    ; We're done.
_swlimm LXI     H,1         ; Immediate word, so push 1
            PUSH    H           ; ..to the stack.
            JMP     _swldone    ; We're done.
_swlnextwordde POP  D           ; Restore DE (which is now pointing at a char).
_swlnextword .inxNfaToLfa D     ; Move to the word's LFA,
            .byte 0EDH                ; ..get the LFA in HL,
            XCHG                ; ..put the LFA into DE,
            LHLD    holdh       ; ..and restore HL.
.ifdef phash
            MOV     A,D         ; The phash routine ignores the LFA, so
            ANI     80H         ; ..see if we are in RAM -- or
            ORA     B           ; ..we are not in the FORTH word list -- and
            JNZ     _swlnextword1;..keep traversing the linked list if so;
            JMP     _swlphash   ; ..continue the phash process otherwise.
.endif
_swlnextword1 MOV   A,D         ; Keep searching for a match
            ORA     E           ; ..if the LFA
            JNZ     _swlagain   ; ..is not zero.
_swlfail LXI     H,0         ; Push false
            PUSH    H           ; ..to the stack.
_swldone .restoreDe
            .restoreBc
            .next

.ifdef phash
; Entry: HL=c-addr A=u (all registers are used)
; Exit : HL=hash values (H1 in H, H2 in L)
_phash PUSH    B           ; Save BC
            PUSH    D           ; ..and DE.
            LXI     D,0         ; Clear the hash values,
            PUSH    D           ; ..which are stored on the stack.
            ORA     A           ; See if the string is zero-length;
            JZ      _phashdone  ; ..and exit if so.
            MOV     C,A         ; Otherwise move the length to A.
_phashnext MOV     A,M         ; Get the next character into A,
            CPI     'a'         ; ..then see if less than 'a';
            JM      _phashnext1 ; ..if so, don't uppercase.
            CPI     'z'+1       ; If greater than 'z'+1,
            JP      _phashnext1 ; ..don't uppercase.
            ANI     11011111b   ; Convert uppercase to lowercase.
_phashnext1 XTHL                ; Swap the string pos with the hashes.
            MOV     B,A         ; Save a copy of the character.
            XRA     H           ; XOR the character with the H1,
            MOV     E,A         ; ..move the PHASHAUX offset into E,
            MVI     D,phashaux1 >> 8;.put the PHASHAUX1 base offset into D,
            LDAX    D           ; ..then lookup the new hash value,
            MOV     H,A         ; ..and move the hash value to H.
            MOV     A,B         ; Get the cached copy of the character.
            XRA     L           ; XOR the character with the H2,
            MOV     E,A         ; ..move the PHASHAUX offset into E,
            MVI     D,phashaux2 >> 8;.put the PHASHAUX2 base offset into D,
            LDAX    D           ; ..then lookup the new hash value,
            MOV     L,A         ; ..and move the hash value to L.
            XTHL                ; Swap the hashes with the string pos.
            INX     H           ; Increment to the next character,
            DCR     C           ; ..decrement the count,
            JNZ     _phashnext  ; ..and keep looping if we count is not zero.
_phashdone POP     H           ; Pop the hash values into HL.
            POP     D           ; Restore DE
            POP     B           ; ..and BC.
            RET                 ; We're done.
.endif


; ----------------------------------------------------------------------
; SET-CURRENT [SEARCH] 16.6.1.2195 ( wid -- )
;
; Set the compilation word list to the word list identified by wid.

            .linkTo searchwordlist,0,11,'T',"NERRUC-TES"
setcurrent JMP     enter
            .word   current,store,exit


; ----------------------------------------------------------------------
; SET-ORDER [SEARCH] 16.6.1.2197 ( widn ... wid1 n -- )
;
; Set the search order to the word lists identified by widn ... wid1.
; Subsequently, word list wid1 will be searched first, and word list
; widn searched last.  If n is zero, empty the search order.  If n is
; minus one, set the search order to the implementation-defined minimum
; search order.  The minimum search order shall include the words
; FORTH-WORDLIST and SET-ORDER.  A system shall allow n to be at least
; eight.
;
; ---
; : SET-ORDER ( widn ... wid1 n --)   0 DO SOESTART I CELLS + ! LOOP ;

            .linkTo setcurrent,0,9,'R',"EDRO-TES"
setorder JMP     enter
            .word   zero,pdo
_setorder1 .word   lit,soestart,i,cells,plus,store,ploop,_setorder1
_setorder2 .word   exit


; ----------------------------------------------------------------------
; WORDLIST [SEARCH] 16.6.1.2460 ( -- wid )
;
; Create a new empty word list, returning its word list identifier wid.
; The new word list may be returned from a pool of preallocated word
; lists or may be dynamically allocated in data space.  A system shall
; allow the creation of at least 8 new word lists in addition to any
; provided as part of the system.

            .linkTo setorder,0,8,'T',"SILDROW"
wordlist JMP     enter
            .word   here,zero,comma,exit



; ======================================================================
; SEARCH Words (implementation details)
; ======================================================================

; ----------------------------------------------------------------------
; #SOES [MFORTH] "num-s-o-es" ( -- n )
;
; Returns the number of word lists n in the search order.
;
; ---
; : #SOES ( --n)
;   CONTEXT DUP  BEGIN DUP @ 0<> WHILE CELL+ REPEAT  SWAP - 2/ ;

            .linkTo wordlist,0,5,'S',"EOS#"
numsoes JMP     enter
            .word   context,dup
_numsoes1 .word   dup,fetch,zeronotequals,zbranch,_numsoes2
            .word   cellplus,branch,_numsoes1
_numsoes2 .word   swap,minus,twoslash,exit


; ----------------------------------------------------------------------
; CONTEXT [MFORTH] ( -- a-addr )
;
; a-addr is the address of a cell that contains a pointer to the first
; word list in the search order.

            .linkTo numsoes,0,7,'T',"XETNOC"
context LXI     H,soestart
            PUSH    H
            .next


; ----------------------------------------------------------------------
; CURRENT [MFORTH] ( -- a-addr )
;
; a-addr is the address of a cell that contains a pointer to the current
; compilation word list.

            .linkTo context,0,7,'T',"NERRUC"
last_search
current LXI     H,tickcurrent
            PUSH    H
            .next
