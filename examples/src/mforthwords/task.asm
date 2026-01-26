; Copyright (c) 2009-2011, Michael Alyn Miller <malyn@strangeGizmo.com>.
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
; TASK Words
; ======================================================================

; ----------------------------------------------------------------------
; PAUSE [MFORTH] ( -- )
;
; Suspend the current task and resume execution of the next task in the
; task list.  PAUSE will return to the caller when all of the tasks in
; the task list have had a chance to execute (and called PAUSE in order
; to relinquish execution to their next task).

            .linkTo link_task,0,5,'E',"SUAP"
pause      ; Suspend the current task.
            PUSH    B           ; Push the return stack pointer.
            PUSH    D           ; Push the instruction pointer.
            LXI     H,0         ; Clear HL
            DAD     SP          ; ..and get SP in HL.
            MVI     E,usersavedsp;Put SAVEDSP variable offset into E
            MOV     D,B         ; ..and put the Task Page into D.
            .byte 0D9H                ; Save the SP in SAVEDSP.

            ; Select the next task (which could be this task).
            LHLD    tickfirsttask;Get the address of the first task,
            MOV     A,H         ; ..move the page address into A,
            LHLD    ticknumtasks; ..get the number of tasks,
            SUB     L           ; ..and calc the page after the last task.

            DCR     B           ; Point B at the presumed next task,
            CMP     B           ; ..and see if we have gone too far;
            JNZ     _pause1     ; ..resume that task if not,
            LHLD    tickfirsttask;..otherwise get the first task
            MOV     B,H         ; ..and resume that task.

            ; Resume the next task.
_pause1 MVI     E,usersavedsp;Get SAVEDSP variable offset into E
            MOV     D,B         ; ..and put the Task Page into D.
            .byte 0EDH                ; Get the saved SP from SAVEDSP
            SPHL                ; ..and restore SP.
            MVI     H,stackguard; Put the stack guard into H
            MVI     L,stackguard; ..and L,
            .byte 0D9H                ; ..and then save the guard to SAVEDSP.
            POP     D           ; Pop the instruction pointer.
            POP     B           ; Pop the return stack pointer.

            .next


; ----------------------------------------------------------------------
; TASK [MFORTH] ( xt -- )
;
; Create a new task and prepare the task to execute xt when it is first
; resumed.  xt should never return, but if it does then the task will be
; put into an infinite PAUSE loop in order to prevent the system from
; freezing.
;
; ---
; : TASK ( xt -- )
;   'FIRSTTASK @ 'NUMTASKS @ 8 LSHIFT - ( xt a-newtaskpage)  1 'NUMTASKS +!
;   [HEX] 7676       OVER [HEX] 80 OR  !     \ Initialize stack guard.
;   10               OVER USERBASE OR  !     \ Initialize BASE.
;   DUP [HEX] FA OR  OVER USERSAVEDSP OR  !  \ Initialize SAVEDSP.
;   SWAP             OVER [HEX] FE OR  !     \ Push xt to the stack.
;   DUP [HEX] 7F OR  OVER [HEX] FC OR  !     \ Push RSP to the stack.
;   ['] STOPPED CFASZ +  OVER [HEX] FA OR  ! \ Push initial IP to the stack.
;   DROP ;

            .linkTo pause,0,4,'K',"SAT"
task JMP     enter
            .word   lit,tickfirsttask,fetch,lit,ticknumtasks,fetch
            .word       lit,8,lshift,minus
            .word   one,lit,ticknumtasks,plusstore
            .word   lit,07676H,over,lit,080H,or,store
            .word   lit,10,over,lit,userbase,or,store
            .word   dup,lit,0FAH,or,over,lit,usersavedsp,or,store
            .word   swap,over,lit,0FEH,or,store
            .word   dup,lit,07FH,or,over,lit,0FCH,or,store
            .word   lit,stopped,lit,cfasz,plus,over,lit,0FAH,or,store
            .word   drop
            .word   exit


; ----------------------------------------------------------------------
; TASK-PAGE [MFORTH] ( -- a-addr )
;
; a-addr is the base address of the Task Page for the current task.

            .linkTo task,0,9,'E',"GAP-KSAT"
taskpage MOV     H,B
            MVI     L,0
            PUSH    H
            .next



; ======================================================================
; TASK Words (implementation details)
; ======================================================================

; ----------------------------------------------------------------------
; STOPPED [MFORTH] ( xt -- )
;
; This word never returns, but instead executes xt and then calls PAUSE
; in an infinite loop if/when that xt returns.  The word is named
; "STOPPED" because the only time it will be the running word is if xt
; returns.
;
; ---
; : STOPPED ( xt -- )   EXECUTE  BEGIN PAUSE AGAIN ;

            .linkTo taskpage,0,7,'D',"EPPOTS"
last_task
stopped JMP     enter
            .word   execute
_stopped1 .word   pause,branch,_stopped1
