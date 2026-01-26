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
; PROFILER Words
; ======================================================================

; ----------------------------------------------------------------------
; PRINT-PROFILE [MFORTH] ( -- )
;
; Print the execution counts and word names for each word in the system
; that was executed at least once in the previous profile run.
;
; ---
; : PRINT-PROFILE ( -- )
;   PRN  LATEST @  BEGIN  DUP NFATOPECSZ + @  ?DUP IF U. DUP .NAME CR THEN
;   NFA>LFA @  DUP 0= UNTIL DROP  [HEX] 0C EMIT  LCD ;

            .linkTo link_profiler,0,13,'E',"LIFORP-TNIRP"
printprofile JMP    enter
            .word   prn,latest,fetch
_printprof1 .word   dup,lit,nfatopecsz,plus,fetch,qdup,zbranch,_printprof2
            .word   udot,dup,dotname,cr
_printprof2 .word   nfatolfa,fetch,dup,zeroequals,zbranch,_printprof1
            .word   drop,lit,0CH,emit,lcd,exit


; ----------------------------------------------------------------------
; PROFILE [MFORTH] ( i*x xt -- j*x )
;
; Profile the given xt.
;
; ---
; : PROFILE ( i*x xt -- j*x)
;   CLEAR-PROFILER  1 PROFILING !  TIMED-EXECUTE  0 PROFILING !
;   TICKS>MS CR ." Total time:" UD. ." ms";

            .linkTo printprofile,0,7,'E',"LIFORP"
profile JMP     enter
            .word   clearprofile,one,lit,profiling,store
            .word   timedexecute
            .word   zero,lit,profiling,store
            .word   tickstoms,cr,psquote,12
            .byte   "Total time: "
            .word   type,uddot,psquote,2
            .byte   "ms"
            .word   type,exit



; ======================================================================
; PROFILER Words (implementation details)
; ======================================================================

; ----------------------------------------------------------------------
; CLEAR-PROFILE [MFORTH] ( -- )
;
; Clear all of the current profiler execution counts.
;
; ---
; : CLEAR-PROFILE ( -- )
;   LATEST @  BEGIN  0 OVER NFATOPECSZ + !  NFA>LFA @  DUP 0= UNTIL DROP ;

            .linkTo profile,0,13,'E',"LIFORP-RAELC"
last_profiler
clearprofile JMP    enter
            .word   latest,fetch
_clearprof1 .word   zero,over,lit,nfatopecsz,plus,store
            .word   nfatolfa,fetch,dup,zeroequals,zbranch,_clearprof1
            .word   drop,exit
