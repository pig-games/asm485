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
; FILE Constants
; ======================================================================

; ----------------------------------------------------------------------
; I/O Result Codes
;
iorok =    0           ; No error.
iorfnf =    1           ; File not found or invalid filename (>6 chars)
iorrdonly =    2           ; Files cannot be opened R/W.
iorbadfileid =   3           ; Bad fileid.



; ======================================================================
; FILE Words
; ======================================================================

; ----------------------------------------------------------------------
; BIN [FILE] 11.6.1.0765 ( fam1 -- fam2 )
;
; Modify the implementation-defined file access method fam1 to additionally
; select a "binary", i.e., not line oriented, file access method, giving
; access method fam2.
;
; ---
; No-op in MFORTH as files are not opened in any specific mode.

            .linkTo link_file,0,3,'N',"IB"
bin .next


; ----------------------------------------------------------------------
; CLOSE-FILE [FILE] 11.6.1.0900 ( fileid -- ior )
;
; Close the file identified by fileid.  ior is the implementation-defined
; I/O result code.
;
; ---
; : CLOSE-FILE ( fileid -- ior)
;   FILEID>FCB? ?DUP IF EXIT THEN
;   FCBADDR +  0 SWAP !  IOROK ;

            .linkTo bin,0,10,'E',"LIF-ESOLC"
closefile JMP     enter
            .word   fileidtofcbq,qdup,zbranch,_closefile1,exit
_closefile1 .word   lit,fcbaddr,plus,zero,swap,store,lit,iorok,exit


; ----------------------------------------------------------------------
; CREATE-FILE [FILE] 11.6.1.1010 ( c-addr u fam -- fileid ior )
;
; Create the file named in the character string specified by c-addr and u,
; and open it with file access method fam.  The meaning of values of fam is
; implementation defined.  If a file with the same name already exists,
; recreate it as an empty file.
;
; If the file was successfully created and opened, ior is zero, fileid is
; its identifier, and the file has been positioned to the start of the file.
;
; Otherwise, ior is the implementation-defined I/O result code and fileid is
; undefined.
;
; ---
; Always fails in MFORTH as the file system is read-only.

            .linkTo closefile,0,11,'E',"LIF-ETAERC"
createfile JMP     enter
            .word   drop,twodrop,zero,lit,iorrdonly,exit


; ----------------------------------------------------------------------
; DELETE-FILE [FILE] 11.6.1.1190 ( c-addr u -- ior )
;
; Delete the file named in the character string specified by c-addr u.
; ior is the implementation-defined I/O result code.
;
; ---
; Always fails in MFORTH as the file system is read-only.

            .linkTo createfile,0,11,'E',"LIF-ETELED"
deletefile JMP     enter
            .word   twodrop,lit,iorrdonly,exit


; ----------------------------------------------------------------------
; FILE-POSITION [FILE] 11.6.1.1520 ( fileid -- ud ior )
;
; ud is the current file position for the file identified by fileid.  ior
; is the implementation-defined I/O result code.  ud is undefined if ior is
; non-zero.
;
; ---
; : FILE-POSITION ( fileid -- ud ior)
;   FILEID>FCB? ?DUP IF 0 SWAP EXIT THEN
;   DUP FCBPOS + @  SWAP FCBADDR + @  -  IOROK ;

            .linkTo deletefile,0,13,'N',"OITISOP-ELIF"
fileposition JMP    enter
            .word   fileidtofcbq,qdup,zbranch,_filepos1,zero,swap,exit
_filepos1 .word   dup,lit,fcbpos,plus,fetch,swap,lit,fcbaddr,plus,fetch
            .word   minus,lit,iorok,exit


; ----------------------------------------------------------------------
; FILE-SIZE [FILE] 11.6.1.1522 ( fileid -- ud ior )
;
; ud is the size, in characters, of the file identified by fileid.  ior
; is the implementation-defined I/O result code.  This operation does not
; affect the value returned by FILE-POSITION.  ud is undefined if ior is
; non-zero.
;
; ---
; : FILE-SIZE ( fileid -- ud ior)
;   FILEID>FCB? ?DUP IF 0 SWAP EXIT THEN
;   DUP FCBEND + @  SWAP FCBADDR + @  -  IOROK ;

            .linkTo fileposition,0,9,'E',"ZIS-ELIF"
filesize JMP    enter
            .word   fileidtofcbq,qdup,zbranch,_filesize1,zero,swap,exit
_filesize1 .word   dup,lit,fcbend,plus,fetch,swap,lit,fcbaddr,plus,fetch
            .word   minus,lit,iorok,exit


; ----------------------------------------------------------------------
; INCLUDE-FILE [FILE] 11.6.1.1717 ( i*x fileid -- j*x )
;
; Remove fileid from the stack.  Save the current input source specification,
; including the current value of SOURCE-ID.  Store fileid in SOURCE-ID.  Make
; the file specified by fileid the input source.  Store zero in BLK.  Other
; stack effects are due to the words INCLUDEd.
;
; Repeat until end of file:  read a line from the file, fill the input buffer
; from the contents of that line, set >IN to zero, and interpret.
;
; Text interpretation begins at the file position where the next file read
; would occur.
;
; When the end of the file is reached, close the file and restore the input
; source specification to its saved value.
;
; An ambiguous condition exists if fileid is invalid, if there is an I/O
; exception reading fileid, or if an I/O exception occurs while closing
; fileid.  When an ambiguous condition exists, the status (open or closed)
; of any files that were being interpreted is implementation-defined.
;
; ---
; \ TODO: Store zero in BLK.
; : INCLUDE-FILE  ( i*x fileid -- j*x)
;   PUSHICB  ICB ICBSOURCEID + !
;   BEGIN  SOURCE-ID FILEID>FCB DUP  2@ <>  WHILE
;       DUP @ ( fcb start) OVER NEXT-LINE ( fcb start end crlfend)
;       -ROT ICB 2! ( fcb crlfend) SWAP !
;       INTERPRET
;   REPEAT
;   DROP  SOURCE-ID CLOSE-FILE DROP  POPICB ;

            .linkTo filesize,0,12,'E',"LIF-EDULCNI"
includefile JMP     enter
            .word   pushicb,icb,lit,icbsourceid,plus,store
_includefile1 .word sourceid,fileidtofcb,dup
            .word       twofetch,notequals,zbranch,_includefile2
            .word   dup,fetch,over,nextline
            .word   dashrot,icb,twostore,swap,store
            .word   interpret,branch,_includefile1
_includefile2 .word drop,sourceid,closefile,drop,popicb,exit



; ----------------------------------------------------------------------
; INCLUDED [FILE] 11.6.1.1718 ( i*x c-addr u -- j*x )
;
; Remove c-addr u from the stack.  Save the current input source specification,
; including the current value of SOURCE-ID.  Open the file specified by
; c-addr u, store the resulting fileid in SOURCE-ID, and make it the input
; source.  Store zero in BLK.  Other stack effects are due to the words
; included.
;
; Repeat until end of file:  read a line from the file, fill the input buffer
; from the contents of that line, set >IN to zero, and interpret.
;
; Text interpretation begins at the file position where the next file read
; would occur.
;
; When the end of the file is reached, close the file and restore the input
; source specification to its saved value.
;
; An ambiguous condition exists if the named file can not be opened, if an I/O
; exception occurs reading the file, or if an I/O exception occurs while
; closing the file.  When an ambiguous condition exists, the status (open or
; closed) of any files that were being interpreted is implementation-defined.
;
; ---
; : INCLUDED ( i*x c-addr u -- j*x)
;   R/O OPEN-FILE ABORT" Unknown file" INCLUDE-FILE ;

            .linkTo includefile,0,8,'D',"EDULCNI"
included JMP     enter
            .word   ro,openfile,zbranch,_included1
            .word   psquote,12
            .byte   "Unknown file"
            .word   type,abort
_included1 .word   includefile,exit


; ----------------------------------------------------------------------
; OPEN-FILE [FILE] 11.6.1.1970 ( c-addr u fam -- fileid ior )
;
; Open the file named in the character string specified by c-addr u,
; with file access method indicated by fam.  The meaning of values of
; fam is implementation defined.
;
; If the file is successfully opened, ior is zero, fileid is its identifier,
; and the file has been positioned to the start of the file.
;
; Otherwise, ior is the implementation-defined I/O result code and fileid
; is undefined.
;
; ---
; : OPEN-FILE ( c-addr u fam -- fileid ior)
;   R/O <> IF 2DROP 0 IORRDONLY EXIT THEN
;   FIND-FILE ?DUP IF 0 SWAP EXIT THEN  NEW-FCB >R  ( file-addr file-len  R:fcb)
;   OVER + R@ FCBEND + !
;   DUP R@ FCBADDR + !  R@ FCBPOS + !
;   R@ FCBGENNUM + DUP C@ 1+ SWAP C!
;   R> FCB>FILEID IOROK ;

            .linkTo included,0,9,'E',"LIF-NEPO"
openfile JMP     enter
            .word   ro,notequals,zbranch,_openfile1
            .word   twodrop,zero,lit,iorrdonly,exit
_openfile1 .word   findfile,qdup,zbranch,_openfile2
            .word   zero,swap,exit
_openfile2 .word   newfcb,tor
            .word   over,plus,rfetch,lit,fcbend,plus,store
            .word   dup,rfetch,lit,fcbaddr,plus,store
            .word       rfetch,lit,fcbpos,plus,store
            .word   rfetch,lit,fcbgennum,plus,dup,cfetch,oneplus,swap,cstore
            .word   rfrom,fcbtofileid,lit,iorok,exit


; ----------------------------------------------------------------------
; R/O [FILE] 11.6.1.2054 "r-o" ( -- fam )
;
; fam is the implementation-defined value for selecting the "read only"
; file access method.

            .linkTo openfile,0,3,'O',"/R"
ro JMP     enter
            .word   lit,00000001b,exit


; ----------------------------------------------------------------------
; R/W [FILE] 11.6.1.2056 "r-w" ( -- fam )
;
; fam is the implementation-defined value for selecting the "read/write"
; file access method.

            .linkTo ro,0,3,'W',"/R"
rw JMP     enter
            .word   lit,00000011b,exit


; ----------------------------------------------------------------------
; READ-FILE [FILE] 11.6.1.2080 ( c-addr u1 fileid -- u2 ior )
;
; Read u1 consecutive characters to c-addr from the current position of the
; file identified by fileid.
;
; If u1 characters are read without an exception, ior is zero and u2 is equal
; to u1.
;
; If the end of the file is reached before u1 characters are read, ior is zero
; and u2 is the number of characters actually read.
;
; If the operation is initiated when the value returned by FILE-POSITION is
; equal to the value returned by FILE-SIZE for the file identified by fileid,
; ior is zero and u2 is zero.
;
; If an exception occurs, ior is the implementation-defined I/O result code,
; and u2 is the number of characters transferred to c-addr without an exception.
;
; An ambiguous condition exists if the operation is initiated when the value
; returned by FILE-POSITION is greater than the value returned by FILE-SIZE
; for the file identified by fileid, or if the requested operation attempts
; to read portions of the file not written.
;
; At the conclusion of the operation, FILE-POSITION returns the next file
; position after the last character read.
;
; ---
; \ u1 bytes are copied first, then u2 is determined later.  We might "read"
; \ more bytes than are remaining, but that's not an issue for us given that
; \ all of our files are in memory anyway.
; : READ-FILE ( c-addr u1 fileid -- u2 ior)
;   FILEID>FCB? ?DUP IF NIP NIP 0 SWAP EXIT THEN  ( ca u1 fcb)
;   DUP >R @ ( ca u1 pos R:fcb) -ROT DUP >R MOVE R> ( u1 R:fcb)
;   R@ 2@ - ( u1 rem R:fcb) MIN  DUP R> ( cnt cnt fcb) +!  IOROK ;

            .linkTo rw,0,9,'E',"LIF-DAER"
readfile JMP    enter
            .word   fileidtofcbq,qdup,zbranch,_readfile1,nip,nip,zero,swap,exit
_readfile1 .word   dup,tor,fetch,dashrot,dup,tor,move,rfrom
            .word   rfetch,twofetch,minus,min
            .word   dup,rfrom,plusstore,lit,iorok,exit


; ----------------------------------------------------------------------
; READ-LINE [FILE] 11.6.1.2090 ( c-addr u1 fileid -- u2 flag ior )
;
; Read the next line from the file specified by fileid into memory at the
; address c-addr.  At most u1 characters are read.  Up to two implementation-
; defined line-terminating characters may be read into memory at the end of
; the line, but are not included in the count u2.  The line buffer provided
; by c-addr should be at least u1+2 characters long.
;
; If the operation succeeded, flag is true and ior is zero.  If a line
; terminator was received before u1 characters were read, then u2 is the
; number of characters, not including the line terminator, actually read
; (0 <= u2 <= u1).  When u1 = u2, the line terminator has yet to be reached.
;
; If the operation is initiated when the value returned by FILE-POSITION is
; equal to the value returned by FILE-SIZE for the file identified by fileid,
; flag is false, ior is zero, and u2 is zero.  If ior is non-zero, an
; exception occurred during the operation and ior is the implementation-
; defined I/O result code.
;
; An ambiguous condition exists if the operation is initiated when the value
; returned by FILE-POSITION is greater than the value returned by FILE-SIZE
; for the file identified by fileid, or if the requested operation attempts
; to read portions of the file not written.
;
; At the conclusion of the operation, FILE-POSITION returns the next file
; position after the last character read.
;
; ---
; : READ-LINE ( c-addr u1 fileid -- u2 flag ior)
;   FILEID>FCB? ?DUP IF NIP NIP 0 SWAP EXIT THEN  ( ca u1 fcb)
;   DUP 2@ - 0= IF DROP 2DROP 0 0 IOROK EXIT THEN
;   DUP >R @ ( ca u1 pos R:fcb) -ROT COPY-LINE ( u2 cnt R:fcb)
;   R> +! -1 IOROK ;

            .linkTo readfile,0,9,'E',"NIL-DAER"
readline JMP    enter
            .word   fileidtofcbq,qdup,zbranch,_readline1,nip,nip,zero,swap,exit
_readline1 .word   dup,twofetch,minus,zeroequals,zbranch,_readline2
            .word       drop,twodrop,zero,zero,lit,iorok,exit
_readline2 .word   dup,tor,fetch,dashrot,copyline
            .word   rfrom,plusstore,lit,-1,lit,iorok,exit


; ----------------------------------------------------------------------
; REPOSITION-FILE [FILE] 11.6.1.2142 ( ud fileid -- ior )
;
; Reposition the file identified by fileid to ud.  ior is the implementation-
; defined I/O result code.  An ambiguous condition exists if the file is
; positioned outside the file boundaries.
;
; At the conclusion of the operation, FILE-POSITION returns the value ud.
;
; ---
; : REPOSITION-FILE ( ud fileid -- ior)
;   FILEID>FCB? ?DUP IF DROP EXIT THEN  DUP  FCBADDR + @ ROT +  SWAP !  IOROK ;

            .linkTo readline,0,15,'E',"LIF-NOITISOPER"
reposfile JMP    enter
            .word   fileidtofcbq,qdup,zbranch,_reposfile,drop,exit
_reposfile .word   dup,lit,fcbaddr,plus,fetch,rot,plus,swap,store
            .word   lit,iorok,exit


; ----------------------------------------------------------------------
; RESIZE-FILE [FILE] 11.6.1.2147 ( ud fileid -- ior )
;
; Set the size of the file identified by fileid to ud.  ior is the
; implementation-defined I/O result code.
;
; If the resultant file is larger than the file before the operation, the
; portion of the file added as a result of the operation might not have been
; written.
;
; At the conclusion of the operation, FILE-SIZE returns the value ud and
; FILE-POSITION returns an unspecified value.
;
; ---
; Always fails in MFORTH as the file system is read-only.

            .linkTo reposfile,0,11,'E',"LIF-EZISER"
resizefile JMP     enter
            .word   twodrop,lit,iorrdonly,exit


; ----------------------------------------------------------------------
; W/O [FILE] 11.6.1.2425 "w-o" ( -- fam )
;
; fam is the implementation-defined value for selecting the "write only"
; file access method.

            .linkTo resizefile,0,3,'O',"/W"
wo JMP     enter
            .word   lit,00000010b,exit


; ----------------------------------------------------------------------
; WRITE-FILE [FILE] 11.6.1.2480 ( c-addr u fileid -- ior )
;
; Write u characters from c-addr to the file identified by fileid starting
; at its current position.  ior is the implementation-defined I/O result code.
;
; At the conclusion of the operation, FILE-POSITION returns the next file
; position after the last character written to the file, and FILE-SIZE returns
; a value greater than or equal to the value returned by FILE-POSITION.
;
; ---
; Always fails in MFORTH as the file system is read-only.

            .linkTo wo,0,10,'E',"LIF-ETIRW"
writefile JMP     enter
            .word   drop,twodrop,lit,iorrdonly,exit


; ----------------------------------------------------------------------
; WRITE-LINE [FILE] 11.6.1.2485 ( c-addr u fileid -- ior )
;
; Write u characters from c-addr followed by the implementation-dependent
; line terminator to the file identified by fileid starting at its current
; position.  ior is the implementation-defined I/O result code.
;
; At the conclusion of the operation, FILE-POSITION returns the next file
; position after the last character written to the file, and FILE-SIZE returns
; a value greater than or equal to the value returned by FILE-POSITION.
;
; ---
; Always fails in MFORTH as the file system is read-only.

            .linkTo writefile,0,10,'E',"NIL-ETIRW"
writeline JMP     enter
            .word   drop,twodrop,lit,iorrdonly,exit



; ======================================================================
; FILE Constants (implementation details)
; ======================================================================

; ----------------------------------------------------------------------
; File Control Block
;
; Stores information about an open file.  The elements are ordered such
; that 2@ on an FCB will put END and POS on the stack in that order.  You
; can then calculate the remaining bytes in the file (the most common
; operation on an FCB if you assume that READ-* is the most commonly-called
; FILE word) with "2@ -" and without any indexing into the FCB.  This is
; also the reason that we store the end address of the file instead of the
; length of the file; we only need the length for FILE-SIZE, but we need
; the end address for every READ-* (to ensure that we do not read past the
; end of the file).  Finally, storing POS first means that you can access
; the absolute file position without having to adjust the FCB address.  In
; other words, an FCB address is also the address of the POS cell for that
; FCB.

fcbpos =    0           ; Offset from FCB to position in file.
fcbend =    2           ; Offset to end address of file.
fcbaddr =    4           ; Offset to address of file.
fcbgennum =    6           ; Offset to generation number.


; ======================================================================
; FILE Words (implementation details)
; ======================================================================

; ----------------------------------------------------------------------
; FCB>FILEID [MFORTH] "fcb-to-fileid" ( fcb-addr -- fileid )
;
; Return fileid given a valid File Control Block address (fcb-addr).
;
; Note that we add one to the zero-based file address in order to support
; the semantics of SOURCE-ID, which requires that zero refer to the user
; input device.  The first FCB, when its generation number is zero, would
; otherwise produce a fileid of zero.
;
; ---
; : FCB>FILEID ( fcb-addr -- fileid)
;   DUP FCBGENNUM + C@ 8 LSHIFT  SWAP FCBSTART - 1+  OR ;

            .linkTo writeline,0,10,'D',"IELIF>BCF"
fcbtofileid JMP     enter
            .word   dup,lit,fcbgennum,plus,cfetch,lit,8,lshift
            .word   swap,lit,fcbstart,minus,oneplus,or,exit


; ----------------------------------------------------------------------
; FILEID>FCB [MFORTH] "fileid-to-fcb" ( fileid -- fcb-addr )
;
; Return the address of the File Control Block for the given fileid.  An
; ambiguous condition exists if fileid is invalid.
;
; ---
; : FILEID>FCB ( fileid -- fcb-addr)   255 AND 1- FCBSTART + ;

            .linkTo fcbtofileid,0,10,'B',"CF>DIELIF"
fileidtofcb JMP    enter
            .word   lit,255,and,oneminus,lit,fcbstart,plus,exit


; ----------------------------------------------------------------------
; FILEID>FCB? [MFORTH] "fileid-to-fcb-question" ( fileid -- ior | fcb-addr 0 )
;
; Return the address of the File Control Block for the given fileid, or
; ior if the fileid is invalid.
;
; ---
; : FILEID>FCB? ( fileid -- ior | fcb-addr 0 )
;   DUP 8 RSHIFT  SWAP 255 AND ( gen fcboff)
;   DUP 0=  OVER [ MAXFCBS 2* 2* 2* ] >  OR IF 2DROP IORBADFILEID EXIT THEN
;   1- FCBSTART +  DUP FCBGENNUM + C@ ROT <> IF DROP IORBADFILEID EXIT THEN
;   DUP FCBADDR + @ 0= IF DROP IORBADFILEID EXIT THEN
;   IOROK ;

            .linkTo fileidtofcb,0,11,'?',"BCF>DIELIF"
fileidtofcbq JMP    enter
            .word   dup,lit,8,rshift,swap,lit,255,and
            .word   dup,zeroequals,over,lit,maxfcbs*8,greaterthan
            .word       or,zbranch,_fileidtofcbq1
            .word   twodrop,lit,iorbadfileid,exit
_fileidtofcbq1 .word oneminus,lit,fcbstart,plus,dup,lit,fcbgennum,plus
            .word       cfetch,rot,notequals,zbranch,_fileidtofcbq2
            .word   drop,lit,iorbadfileid,exit
_fileidtofcbq2 .word dup,lit,fcbaddr,plus,fetch,zeroequals,zbranch,_fileidtofcbq3
            .word       drop,lit,iorbadfileid,exit
_fileidtofcbq3 .word lit,iorok,exit


; ----------------------------------------------------------------------
; FIND-FILE [MFORTH] "find-file" ( c-addr u -- ior | file-addr file-len 0 )
;
; Find the file named in the character string specified by c-addr u.  No
; extension is expected, FIND-FILE will append the ".DO" extension.  If
; the file is found the address and length of the file and 0 will be
; returned, otherwise an ior will be returned.
;
; ---
; : FIND-FILE ( ca u -- ior | fa fl 0)
;   DUP 6 > IF 2DROP IORFNF EXIT THEN
;   TUCK  FILNAME SWAP MOVE
;   6 SWAP ( 6 u) ?DO BL FILNAME I + C! LOOP
;   FILNAME 6 +  [CHAR] D OVER C!  [CHAR] O SWAP 1+ C!
;   SRCNAM ;

            .linkTo fileidtofcbq,0,9,'E',"LIF-DNIF"
findfile JMP     enter
            .word   dup,lit,6,greaterthan,zbranch,_findfile1
            .word   twodrop,lit,iorfnf,exit
_findfile1 .word   tuck,lit,0FC93H,swap,move
            .word   lit,6,swap,pqdo,_findfile3
_findfile2 .word   bl,lit,0FC93H,i,plus,cstore,ploop,_findfile2
_findfile3 .word   lit,0FC93H,lit,6,plus
            .word   lit,'D',over,cstore,lit,'O',swap,oneplus,cstore
            .word   srcnam,exit


; ----------------------------------------------------------------------
; INIT-FCBS [MFORTH] "init-fcbs" ( -- )
;
; Initialize all of the File Control Blocks.  This has the effect of
; "closing" any open files.
;
; ---
; : INIT-FCBS ( -- )   FCBSTART [ MAXFCBS 2* 2* 2* ] 0 FILL ;

            .linkTo findfile,0,9,'S',"BCF-TINI"
initfcbs JMP     enter
            .word   lit,fcbstart,lit,maxfcbs*8,zero,fill,exit


; ----------------------------------------------------------------------
; NEW-FCB [MFORTH] "new-fcb" ( -- 0 | fcb-addr )
;
; Find and return the address of an unused (and uninitialized) File
; Control Block.  Return 0 if the system has run out of File Control
; Blocks.
;
; ---
; : NEWFCB ( -- fcb-addr)
;   [ MAXFCBS 2* 2* 2* ] LITERAL 0 DO
;   FCBSTART I +  DUP FCBADDR + @ 0= IF UNLOOP EXIT THEN  DROP  8 +LOOP
;   0 ;

            .linkTo initfcbs,0,7,'B',"CF-WEN"
newfcb JMP     enter
            .word   lit,maxfcbs*8,zero,pdo
_newfcb1 .word   lit,fcbstart,i,plus,dup,lit,fcbaddr,plus,fetch
            .word   zeroequals,zbranch,_newfcb2,unloop,exit
_newfcb2 .word   drop,lit,8,pplusloop,_newfcb1
            .word   zero,exit


; ----------------------------------------------------------------------
; NEXT-LINE [MFORTH] ( fcb -- addr1 addr2 )
;
; Read forward from the current position in the file identified by fcb
; until either a CRLF sequence is found or the end of file is reached.
; addr1 is the address of the end of the current line in the file (ignoring
; the CRLF sequence, if any).  addr2 is the address of the end of the current
; line, including the CRLF sequence.  addr2 will normally be addr1+2 if the
; line was terminated with a CRLF.
;
; ---
; \ The loop in this method takes advantage of the fact that all M100 files
; \ end with an EOF and so we can always read the next two characters in the
; \ file, even if this is the last character in the file.  We will never read
; \ a byte from another file in this situation, because the second character
; \ will be EOF.
; : NEXT-LINE ( fcb -- addr1 addr2)
;   2@ TUCK - 2>B FORB B @ 0x0A0D = IF B DUP 1+ 1+ EXIT THEN NEXTB B DUP ;

            .linkTo newfcb,0,9,'E',"NIL-TXEN"
nextline POP     H           ; Get FCB into HL.
            MOV     A,M         ; Get the FCBPOS[l] into A,
            INX     H           ; ..increment to FCBPOS[h],
            MOV     H,M         ; ..put FCBPOS[h] into H,
            MOV     L,A         ; ..then put FCBPOS[l] into L.
_nextline1 MOV     A,M         ; Get the next byte into A,
            CPI     01AH        ; ..see if it is EOF,
            JZ      _nextlineeof; ..and then exit if so.
            CPI     00DH        ; See if it is CR,
            INX     H           ; ..move to the next byte,
            JNZ     _nextline1  ; ..and continue looping if not CR.
            MOV     A,M         ; See if the byte after CR
            CPI     00AH        ; ..is LF,
            JNZ     _nextline1  ; ..and if not then continue looping.
            DCX     H           ; Otherwise decrement HL to before the CR,
            PUSH    H           ; ..push addr1,
            INX     H           ; ..increment past the CR
            INX     H           ; ..and LF,
            PUSH    H           ; ..then push addr2.
            JMP     _nextlinedone;We're done.
_nextlineeof PUSH   H           ; Push addr1.
            PUSH    H           ; Push addr2.
_nextlinedone .next


; ----------------------------------------------------------------------
; SRCNAM [MFORTH] ( -- ior | file-addr file-len 0 )
;
; Call the Main ROM's SRCNAM routine.  FILNAM has already been populated
; by the caller.

            .linkTo nextline,0,6,'M',"ANCRS"
last_file
srcnam .saveDe              ; Save DE
            PUSH    B           ; ..and BC, both of which are corrupted.
            CALL    stdcall     ; Call the
            .word   20AFH       ; .."SRCNAM" routine.
            POP     B           ; Restore BC.
            JZ      _srcnamfail ; Zero indicates not found.
            PUSH    D           ; Push file-addr to the stack.
            XCHG                ; Get file-addr in HL.
            LXI     D,0         ; Initialize file-len to zero.
_srcnam1 MOV     A,M         ; Get the next byte of the file into A,
            CPI     01AH        ; ..see if it is EOF,
            JZ      _srcnam2    ; ..and exit the loop if so.
            INX     D           ; Increment the file-len,
            INX     H           ; ..increment the file pointer,
            JMP     _srcnam1    ; ..and continue looping.
_srcnam2 PUSH    D           ; Push file-len onto the stack.
            LXI     H,iorok     ; Put IOROK in HL.
            JMP     _srcnamdone ; We're done.
_srcnamfail LXI     H,iorfnf    ; Put the IOR in HL.
_srcnamdone PUSH    H           ; Push the flag to the stack.
            .restoreDe
            .next
