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
; Assembler Words
; ======================================================================

; ----------------------------------------------------------------------
; END-CODE [MFORTH] ( -- )
;
; End the current code definition.  If the data-space pointer is not
; aligned, reserve enough data space to align it.  Restore the previous
; search order.
;
; ---
; : END-CODE ( -- )   PREVIOUS ;

            .linkTo link_assembler,0,8,'E',"DOC-DNE"
endcode JMP     enter
            .word   previous
            .word   exit


; ----------------------------------------------------------------------
; NEXT [MFORTH] ( -- )
;
; Compile the code for NEXT into the current code definition.

            .linkTo endcode,0,4,'T',"XEN"
asmnext JMP     enter
.ifndef profiler
            .word   asmlhlx
            .word   asmopd,asminx
            .word   asmopd,asminx
            .word   asmpchl
.else
            .word   lit,profilenext,asmjmp
.endif
            .word   exit


; ----------------------------------------------------------------------
; ROMCALL [MFORTH] ( addr -- )
;
; Call the Main ROM routine identified by addr.

            .linkTo asmnext,0,7,'L',"LACMOR"
asmromcall JMP  enter
            .word   lit,stdcall,asmcall
            .word   comma
            .word   exit


; ----------------------------------------------------------------------
; RESTOREREGS [MFORTH] ( -- )
;
; Restore BC and DE (corrupts HL).

            .linkTo asmromcall,0,11,'S',"GEREROTSER"
asmrestoreregs JMP  enter
            .word   lit,saveb,asmlhld
            .word   asmoph,asmopb,asmmov
            .word   asmopl,asmopc,asmmov
            .word   lit,saved,asmlhld
            .word   asmxchg
            .word   exit


; ----------------------------------------------------------------------
; SAVEREGS [MFORTH] ( -- )
;
; Save BC and DE (corrupts HL).

            .linkTo asmrestoreregs,0,8,'S',"GEREVAS"
asmsaveregs JMP     enter
            .word   asmopb,asmoph,asmmov
            .word   asmopc,asmopl,asmmov
            .word   lit,saveb,asmshld
            .word   asmxchg
            .word   lit,saved,asmshld
            .word   exit



; ======================================================================
; Control Flow Words
; ======================================================================

            .linkTo asmsaveregs,0,2,'=',"0"
asmzeroequals JMP   enter
            .word   lit,0C2H,exit

            .linkTo asmzeroequals,0,2,'>',"0"
asmzerogreater JMP  enter
            .word   lit,0FAH,exit

            .linkTo asmzerogreater,0,2,'<',"0"
asmzeroless JMP     enter
            .word   lit,0F2H,exit

            .linkTo asmzeroless,0,3,'>',"<0"
asmzeronotequals JMP enter
            .word   lit,0CAH,exit

            .linkTo asmzeronotequals,0,2,'C',"C"
asmcc JMP     enter
            .word   lit,0DAH,exit

            .linkTo asmcc,0,2,'S',"C"
asmcs JMP     enter
            .word   lit,0D2H,exit

            .linkTo asmcs,0,5,'N',"IGEB"
asmbegin JMP     enter
            .word   here,exit

            .linkTo asmbegin,0,4,'E',"SLE"
asmelse JMP     enter
            .word   lit,0C3H,asmif,swap,asmthen,exit

            .linkTo asmelse,0,2,'F',"I"
asmif JMP     enter
            .word   ccomma,here,zero,comma,exit

            .linkTo asmif,0,4,'N',"EHT"
asmthen JMP     enter
            .word   here,swap,store,exit

            .linkTo asmthen,0,6,'T',"AEPER"
asmrepeat JMP     enter
            .word   swap,lit,0C3H,ccomma,comma,asmthen,exit

            .linkTo asmrepeat,0,5,'L',"ITNU"
asmuntil JMP     enter
            .word   ccomma,comma,exit

            .linkTo asmuntil,0,5,'E',"LIHW"
asmwhile JMP     enter
            .word   asmif,exit


; ======================================================================
; 8085 Assembly Instructions
; ======================================================================

; ----------------------------------------------------------------------
; Operands
;

asmOp .macro value
            LXI H,\value
            PUSH H
            .next
.endmacro

            .linkTo0 asmwhile,0,1,'A'
asmopa .asmop 7

            .linkTo0 asmopa,0,1,'B'
asmopb .asmop 0

            .linkTo0 asmopb,0,1,'C'
asmopc .asmop 1

            .linkTo0 asmopc,0,1,'D'
asmopd .asmop 2

            .linkTo0 asmopd,0,1,'E'
asmope .asmop 3

            .linkTo0 asmope,0,1,'H'
asmoph .asmop 4

            .linkTo0 asmoph,0,1,'L'
asmopl .asmop 5

            .linkTo0 asmopl,0,1,'M'
asmopm .asmop 6

            .linkTo asmopm,0,3,'W',"SP"
asmoppsw .asmop 6

            .linkTo asmoppsw,0,2,'P',"S"
asmopsp .asmop 6


; ----------------------------------------------------------------------
; Zero-operand instructions
;

asmZeroOp .macro opcode
            JMP enter
            .word lit,\opcode,ccomma,exit
.endmacro

            .linkTo asmopsp,0,4,'R',"HSA"
asmashr .asmzeroop 10H

            .linkTo asmashr,0,3,'A',"MC"
asmcma .asmzeroop 2FH

            .linkTo asmcma,0,3,'C',"MC"
asmcmc .asmzeroop 3FH

            .linkTo asmcmc,0,3,'A',"AD"
asmdaa .asmzeroop 27H

            .linkTo asmdaa,0,2,'I',"D"
asmdi .asmzeroop 0F3H

            .linkTo asmdi,0,4,'B',"USD"
asmdsub .asmzeroop 08H

            .linkTo asmdsub,0,2,'I',"E"
asmei .asmzeroop 0FBH

            .linkTo asmei,0,3,'T',"LH"
asmhlt .asmzeroop 76H

            .linkTo asmhlt,0,4,'X',"LHL"
asmlhlx .asmzeroop 0EDH

            .linkTo asmlhlx,0,3,'P',"ON"
asmnop .asmzeroop 00H

            .linkTo asmnop,0,4,'L',"HCP"
asmpchl .asmzeroop 0E9H

            .linkTo asmpchl,0,3,'L',"AR"
asmral .asmzeroop 17H

            .linkTo asmral,0,3,'R',"AR"
asmrar .asmzeroop 1FH

            .linkTo asmrar,0,4,'L',"EDR"
asmrdel .asmzeroop 18H

            .linkTo asmrdel,0,3,'T',"ER"
asmret .asmzeroop 0C9H

            .linkTo asmret,0,3,'M',"IR"
asmrim .asmzeroop 20H

            .linkTo asmrim,0,3,'C',"LR"
asmrlc .asmzeroop 07H

            .linkTo asmrlc,0,3,'C',"RR"
asmrrc .asmzeroop 0FH

            .linkTo asmrrc,0,4,'X',"LHS"
asmshlx .asmzeroop 0D9H

            .linkTo asmshlx,0,3,'M',"IS"
asmsim .asmzeroop 30H

            .linkTo asmsim,0,4,'L',"HPS"
asmsphl .asmzeroop 0F9H

            .linkTo asmsphl,0,3,'C',"TS"
asmstc .asmzeroop 37H

            .linkTo asmstc,0,4,'G',"HCX"
asmxchg .asmzeroop 0EBH

            .linkTo asmxchg,0,4,'L',"HTX"
asmxthl .asmzeroop 0E3H


; ----------------------------------------------------------------------
; Register instructions
;

asmRegOp .macro opcode
            JMP enter
            .word lit,\opcode,plus,ccomma,exit
.endmacro

            .linkTo asmxthl,0,3,'C',"DA"
asmadc .asmregop 88H

            .linkTo asmadc,0,3,'D',"DA"
asmadd .asmregop 80H

            .linkTo asmadd,0,3,'A',"NA"
asmana .asmregop 0A0H

            .linkTo asmana,0,3,'P',"MC"
asmcmp .asmregop 0B8H

            .linkTo asmcmp,0,3,'R',"DC"
asmdcr JMP     enter
            .word   eightstar,lit,05H,plus,ccomma,exit

            .linkTo asmdcr,0,3,'R',"NI"
asminr JMP     enter
            .word   eightstar,lit,04H,plus,ccomma,exit

            .linkTo asminr,0,3,'A',"RO"
asmora .asmregop 0B0H

            .linkTo asmora,0,3,'B',"BS"
asmsbb .asmregop 98H

            .linkTo asmsbb,0,3,'B',"US"
asmsub .asmregop 90H

            .linkTo asmsub,0,3,'A',"RX"
asmxra .asmregop 0A8H


; ----------------------------------------------------------------------
; Register pair instructions
;

asmRegpairOp .macro opcode
            JMP enter
            .word eightstar,lit,\opcode,plus,ccomma,exit
.endmacro

            .linkTo asmxra,0,3,'D',"AD"
asmdad .asmregpairop 09H

            .linkTo asmdad,0,3,'X',"CD"
asmdcx .asmregpairop 0BH

            .linkTo asmdcx,0,3,'X',"NI"
asminx .asmregpairop 03H

            .linkTo asminx,0,4,'X',"ADL"
asmldax .asmregpairop 0AH

            .linkTo asmldax,0,3,'P',"OP"
asmpop .asmregpairop 0C1H

            .linkTo asmpop,0,4,'H',"SUP"
asmpush .asmregpairop 0C5H

            .linkTo asmpush,0,4,'X',"ATS"
asmstax .asmregpairop 02H


; ----------------------------------------------------------------------
; Byte operand instructions
;

asmByteOp .macro opcode
            JMP enter
            .word lit,\opcode,ccomma,ccomma,exit
.endmacro

            .linkTo asmstax,0,3,'I',"CA"
asmaci .asmbyteop 0CEH

            .linkTo asmaci,0,3,'I',"DA"
asmadi .asmbyteop 0C6H

            .linkTo asmadi,0,3,'I',"NA"
asmani .asmbyteop 0E6H

            .linkTo asmani,0,3,'I',"PC"
asmcpi .asmbyteop 0FEH

            .linkTo asmcpi,0,2,'N',"I"
asmin .asmbyteop 0DBH

            .linkTo asmin,0,3,'I',"RO"
asmori .asmbyteop 0F6H

            .linkTo asmori,0,3,'T',"UO"
asmout .asmbyteop 0D3H

            .linkTo asmout,0,3,'T',"SR"
asmrst JMP     enter
            .word   eightstar,lit,0C7H,plus,ccomma,exit

            .linkTo asmrst,0,3,'I',"BS"
asmsbi .asmbyteop 0DEH

            .linkTo asmsbi,0,3,'I',"US"
asmsui .asmbyteop 0D6H

            .linkTo asmsui,0,3,'I',"RX"
asmxri .asmbyteop 0EEH


; ----------------------------------------------------------------------
; Word operand instructions
;

asmWordOp .macro opcode
            JMP enter
            .word lit,\opcode,ccomma,comma,exit
.endmacro

            .linkTo asmxri,0,4,'L',"LAC"
asmcall .asmwordop 0CDH

            .linkTo asmcall,0,3,'P',"MJ"
asmjmp .asmwordop 0C3H

            .linkTo asmjmp,0,3,'A',"DL"
asmlda .asmwordop 3AH

            .linkTo asmlda,0,4,'D',"LHL"
asmlhld .asmwordop 2AH

            .linkTo asmlhld,0,4,'D',"LHS"
asmshld .asmwordop 22H

            .linkTo asmshld,0,3,'A',"TS"
asmsta .asmwordop 32H


; ----------------------------------------------------------------------
; Move and Load Immediate instructions
;

            .linkTo asmsta,0,3,'I',"XL"
asmlxi JMP     enter
            .word   eightstar,oneplus,ccomma,comma,exit

            .linkTo asmlxi,0,3,'V',"OM"
asmmov JMP     enter
            .word   eightstar,lit,40H,plus,plus,ccomma,exit

            .linkTo asmmov,0,3,'I',"VM"
last_assembler
asmmvi JMP     enter
            .word   eightstar,lit,06H,plus,ccomma,ccomma,exit
