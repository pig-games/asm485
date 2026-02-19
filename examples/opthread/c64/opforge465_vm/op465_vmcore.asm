; opForge465 C64 native VM core scaffold.
;
; Algorithm sketch for a growable assembler host:
; 1) INIT: validate/reset control block and clear runtime state.
; 2) LOAD_PACKAGE: host hook supplies .opcpu bytes; validate OPCP header.
; 3) SET_PIPELINE: parse cpu_id\0dialect and lock active execution tables.
; 4) TOKENIZE/PARSE/ENCODE: host hook supplies line payload; VM stage executes.
; 5) LAST_ERROR: expose latest error payload for host-side diagnostics retrieval.
;
; Updated size estimate (code only, not .opcpu payload/data buffers):
; - Current measured scaffold code:           ~0.72 KiB (742 bytes)
;   (code_vmcore=686, code_hooks=48, code_main=8 from current map)
; - Tokenizer VM executor + token encoder:    +1.6 to +2.4 KiB
; - Parser VM executor + envelope handlers:   +1.2 to +2.0 KiB
; - TABL resolve + VM encode executor:        +1.4 to +2.3 KiB
; - .opcpu chunk reader/indexer glue:         +1.0 to +1.8 KiB
; - Diagnostics mapping + wire adapters:      +0.4 to +0.9 KiB
; Realistic steady-state VM code target:      ~6.3 to ~10.1 KiB
; Most likely landing zone with current plan: ~7.4 to ~8.6 KiB

.module op465.vmcore
    .cpu 6502
    .use op465.contract as C
    .use op465.data as D
    .use op465.hooks as H
    .pub

.section code_vmcore, align=1
vm_bootstrap_demo:
    lda #$06
    sta C.C64_BGCOLOR
    lda #$0e
    sta C.C64_BORDERCOLOR

    jsr entry_init
    jsr entry_load_package
    jsr entry_set_pipeline
    jsr H.host_hook_open_input_file
    jsr snapshot_last_status
    jsr entry_last_error
    jsr apply_status_color
    rts

entry_init:
    lda #C.ENTRY_ORD_INIT
    sta D.current_entry
    lda #0
    sta D.current_input_len
    jsr prepare_request
    jsr handle_init
    rts

entry_load_package:
    lda #C.ENTRY_ORD_LOAD_PACKAGE
    sta D.current_entry
    jsr H.host_hook_load_opcpu_package
    jsr prepare_request
    jsr handle_load_package
    rts

entry_set_pipeline:
    lda #C.ENTRY_ORD_SET_PIPELINE
    sta D.current_entry
    lda #<D.set_pipeline_payload
    sta D.control_block + C.CB_INPUT_PTR_LO
    lda #>D.set_pipeline_payload
    sta D.control_block + C.CB_INPUT_PTR_HI
    lda #C.SET_PIPELINE_PAYLOAD_LEN
    sta D.current_input_len
    jsr prepare_request
    jsr handle_set_pipeline
    rts

entry_tokenize_line:
    lda #C.ENTRY_ORD_TOKENIZE_LINE
    sta D.current_entry
    jsr H.host_hook_next_source_line
    jsr prepare_request
    jsr handle_tokenize
    rts

entry_parse_line:
    lda #C.ENTRY_ORD_PARSE_LINE
    sta D.current_entry
    jsr H.host_hook_next_source_line
    jsr prepare_request
    jsr handle_parse
    rts

entry_encode_instruction:
    lda #C.ENTRY_ORD_ENCODE_INSTRUCTION
    sta D.current_entry
    jsr H.host_hook_next_source_line
    jsr prepare_request
    jsr handle_encode
    rts

entry_last_error:
    lda #C.ENTRY_ORD_LAST_ERROR
    sta D.current_entry
    lda #0
    sta D.current_input_len
    jsr prepare_request
    jsr handle_last_error
    rts

prepare_request:
    ; request id++
    clc
    lda D.control_block + C.CB_REQUEST_ID_LO
    adc #1
    sta D.control_block + C.CB_REQUEST_ID_LO
    lda D.control_block + C.CB_REQUEST_ID_HI
    adc #0
    sta D.control_block + C.CB_REQUEST_ID_HI

    lda D.current_input_len
    sta D.control_block + C.CB_INPUT_LEN_LO
    lda #0
    sta D.control_block + C.CB_INPUT_LEN_HI
    rts

handle_init:
    lda #$4f
    sta D.control_block + C.CB_MAGIC_0
    lda #$54
    sta D.control_block + C.CB_MAGIC_1
    lda #$36
    sta D.control_block + C.CB_MAGIC_2
    lda #$35
    sta D.control_block + C.CB_MAGIC_3

    lda #$01
    sta D.control_block + C.CB_ABI_VERSION_LO
    lda #$00
    sta D.control_block + C.CB_ABI_VERSION_HI

    lda #C.CB_SIZE
    sta D.control_block + C.CB_STRUCT_SIZE_LO
    lda #$00
    sta D.control_block + C.CB_STRUCT_SIZE_HI

    lda #C.CAP_FLAGS_V1
    sta D.control_block + C.CB_CAP_FLAGS_LO
    lda #$00
    sta D.control_block + C.CB_CAP_FLAGS_HI

    lda #0
    sta D.package_is_loaded
    sta D.pipeline_is_set

    lda #C.STATUS_OK
    ldy #0
    jsr set_status
    jsr clear_output_len
    jsr clear_last_error_len
    rts

handle_load_package:
    lda D.control_block + C.CB_INPUT_PTR_LO
    sta C.ZP_INPUT_PTR_LO
    sta D.loaded_pkg_ptr_lo
    lda D.control_block + C.CB_INPUT_PTR_HI
    sta C.ZP_INPUT_PTR_HI
    sta D.loaded_pkg_ptr_hi
    lda D.control_block + C.CB_INPUT_LEN_LO
    sta D.loaded_pkg_len_lo
    lda D.control_block + C.CB_INPUT_LEN_HI
    sta D.loaded_pkg_len_hi

    lda #0
    sta D.package_is_loaded
    sta D.pipeline_is_set

    lda C.ZP_INPUT_PTR_LO
    ora C.ZP_INPUT_PTR_HI
    beq load_package_bad_request

    lda D.loaded_pkg_len_hi
    bne load_package_check_header
    lda D.loaded_pkg_len_lo
    cmp #C.OPCPU_HEADER_LEN
    bcc load_package_bad_request

load_package_check_header:
    ldy #0
    lda (C.ZP_INPUT_PTR_LO), y
    cmp #$4f
    bne load_package_bad_header
    iny
    lda (C.ZP_INPUT_PTR_LO), y
    cmp #$50
    bne load_package_bad_header
    iny
    lda (C.ZP_INPUT_PTR_LO), y
    cmp #$43
    bne load_package_bad_header
    iny
    lda (C.ZP_INPUT_PTR_LO), y
    cmp #$50
    bne load_package_bad_header

    iny
    lda (C.ZP_INPUT_PTR_LO), y
    cmp #$01
    bne load_package_bad_header
    iny
    lda (C.ZP_INPUT_PTR_LO), y
    cmp #$00
    bne load_package_bad_header

    iny
    lda (C.ZP_INPUT_PTR_LO), y
    cmp #$34
    bne load_package_bad_header
    iny
    lda (C.ZP_INPUT_PTR_LO), y
    cmp #$12
    bne load_package_bad_header

    lda #1
    sta D.package_is_loaded
    lda #C.STATUS_OK
    ldy #0
    jsr set_status
    jsr clear_output_len
    jsr clear_last_error_len
    rts

load_package_bad_request:
    lda #C.OTR_BAD_REQ_ERROR_LEN
    jsr set_bad_request_len
    rts

load_package_bad_header:
    lda #C.OPC_BAD_HEADER_LEN
    jsr set_runtime_error_len
    rts

handle_set_pipeline:
    lda D.package_is_loaded
    bne set_pipeline_check_ptr
    lda #C.OTR_NO_PACKAGE_ERROR_LEN
    jsr set_runtime_error_len
    rts

set_pipeline_check_ptr:
    lda D.control_block + C.CB_INPUT_PTR_LO
    sta C.ZP_INPUT_PTR_LO
    lda D.control_block + C.CB_INPUT_PTR_HI
    sta C.ZP_INPUT_PTR_HI
    lda C.ZP_INPUT_PTR_LO
    ora C.ZP_INPUT_PTR_HI
    bne set_pipeline_check_len
    lda #C.OTR_BAD_REQ_ERROR_LEN
    jsr set_bad_request_len
    rts

set_pipeline_check_len:
    lda D.control_block + C.CB_INPUT_LEN_HI
    bne set_pipeline_bad_request
    lda D.control_block + C.CB_INPUT_LEN_LO
    cmp #C.SET_PIPELINE_MIN_LEN
    bcs set_pipeline_find_separator
set_pipeline_bad_request:
    lda #C.OTR_BAD_REQ_ERROR_LEN
    jsr set_bad_request_len
    rts

set_pipeline_find_separator:
    ldy #0
set_pipeline_find_separator_loop:
    cpy D.control_block + C.CB_INPUT_LEN_LO
    beq set_pipeline_bad_request
    lda (C.ZP_INPUT_PTR_LO), y
    beq set_pipeline_separator_found
    iny
    bne set_pipeline_find_separator_loop
    beq set_pipeline_bad_request

set_pipeline_separator_found:
    cpy #0
    beq set_pipeline_bad_request
    cpy #C.SET_PIPELINE_CPU_LEN
    bne set_pipeline_unsupported

    ldy #0
set_pipeline_compare_cpu_loop:
    lda (C.ZP_INPUT_PTR_LO), y
    cmp D.set_pipeline_payload, y
    bne set_pipeline_unsupported
    iny
    cpy #C.SET_PIPELINE_CPU_LEN
    bne set_pipeline_compare_cpu_loop

    lda D.control_block + C.CB_INPUT_LEN_LO
    cmp #C.SET_PIPELINE_PAYLOAD_LEN
    bne set_pipeline_unsupported

    lda #1
    sta D.pipeline_is_set
    lda #C.STATUS_OK
    ldy #0
    jsr set_status
    jsr clear_output_len
    jsr clear_last_error_len
    rts

set_pipeline_unsupported:
    lda #C.OTR_BAD_PIPELINE_LEN
    jsr set_runtime_error_len
    rts

handle_tokenize:
    ; VM pseudocode: TOKENIZE_LINE execution model (authoritative tokenizer lane)
    ;
    ; in:
    ; - D.control_block + CB_INPUT_PTR/CB_INPUT_LEN = source line bytes.
    ; - active pipeline already selected by handle_set_pipeline.
    ;
    ; stage 0: request guards
    ; if D.pipeline_is_set == 0 -> runtime error "OTR_NO_PIPELINE"
    ; if input ptr == null or input_len invalid -> bad request "OTR_BAD_REQ"
    ;
    ; stage 1: resolve tokenizer program
    ; program = resolve_tokenizer_vm_program(owner precedence):
    ;   dialect(TKVM) -> cpu(TKVM) -> family(TKVM)
    ; limits  = min(package TKVM limits, runtime retro profile limits)
    ; diagmap = resolve tokenizer diagnostic catalog from package
    ;
    ; stage 2: execute tokenizer VM bytecode (TokenizerVmOpcode)
    ; instruction set used by runtime:
    ;   0x01 ReadChar, 0x02 Advance, 0x03 StartLexeme, 0x04 PushChar
    ;   0x05 EmitToken(kind), 0x06 SetState(u16), 0x07 Jump(u32)
    ;   0x08 JumpIfEol(u32), 0x09 JumpIfByteEq(u8,u32), 0x0A JumpIfClass(u8,u32)
    ;   0x0B Fail(reason), 0x0C EmitDiag(slot), 0x0E ScanCoreToken, 0x00 End
    ;   0x0D DelegateCore exists but is rejected in authoritative VM mode
    ; loop model:
    ;   ReadChar -> classify via JumpIfClass/JumpIfByteEq -> StartLexeme/PushChar
    ;   EmitToken(kind) when token boundary is reached -> Advance or SetState/Jump
    ;   terminate on End
    ; enforce limits each step: max_steps_per_line, max_tokens_per_line,
    ; max_lexeme_bytes, max_errors_per_line
    ;
    ; stage 3: encode output payload
    ; write portable token array to output buffer (length-prefixed records):
    ;   [kind][span_start][span_end][lexeme_len][lexeme bytes...]
    ; set CB_OUTPUT_LEN to encoded token payload bytes
    ; clear CB_LAST_ERROR_LEN
    ; set STATUS_OK
    ;
    ; stage 4: deterministic failures from opcode paths
    ; tokenizer missing/invalid program -> runtime error namespace "ott_*"
    ; unknown opcode / invalid state / Fail / EmitDiag / budget overflow -> "ott_*"
    ; malformed request shapes -> bad request namespace "OTR_BAD_REQ"
    jsr set_unimplemented_runtime_error
    rts

handle_parse:
    ; VM pseudocode: PARSE_LINE execution model (line-envelope parser VM lane)
    ;
    ; in:
    ; - source line payload (or token payload in future wire revision).
    ; - active pipeline and parser contract selected by set_pipeline.
    ;
    ; stage 0: request guards
    ; if pipeline not set -> runtime error "OTR_NO_PIPELINE"
    ; if input buffer invalid -> bad request "OTR_BAD_REQ"
    ;
    ; stage 1: get parse-ready token stream
    ; if request contains raw line bytes:
    ;   run tokenize stage internally (same rules as handle_tokenize)
    ; else:
    ;   decode provided portable token payload
    ; reject token stream above parser budget (deterministic "otp_*" error)
    ;
    ; stage 2: resolve parser envelope program
    ; parser_program = resolve parser VM program with owner precedence:
    ;   dialect(PAVM) -> cpu(PAVM) -> family(PAVM)
    ; parser_contract = validate grammar/opcode/ast schema compatibility
    ;
    ; stage 3: execute parser VM bytecode (ParserVmOpcode)
    ; instruction set used by runtime:
    ;   0x04 ParseStatementEnvelope
    ;   0x05 ParseDotDirectiveEnvelope
    ;   0x06 ParseAssignmentEnvelope
    ;   0x07 ParseInstructionEnvelope
    ;   0x08 ParseStarOrgEnvelope
    ;   0x09 EmitDiagIfNoAst(slot)
    ;   0x02 EmitDiag(slot), 0x03 Fail, 0x00 End
    ; loop model:
    ;   try envelope parse opcodes in deterministic order
    ;   first successful envelope sets parsed_line AST
    ;   EmitDiag/EmitDiagIfNoAst produce parser diagnostic codes
    ;   End returns AST or deterministic "ended without AST" error
    ;
    ; stage 4: encode AST output
    ; write PortableLineAst payload for downstream encode stage:
    ;   [line_kind][node_count][node records...]
    ; set CB_OUTPUT_LEN to AST payload size
    ; clear CB_LAST_ERROR_LEN
    ; set STATUS_OK
    ;
    ; stage 5: deterministic failures from opcode paths
    ; parser contract/version mismatch -> runtime error namespace "otp_*"
    ; invalid opcode / EmitDiag / Fail / End-without-AST -> runtime error "otp_*"
    ; malformed request shapes -> bad request namespace "OTR_BAD_REQ"
    jsr set_unimplemented_runtime_error
    rts

handle_encode:
    ; VM pseudocode: ENCODE_INSTRUCTION execution model (TABL encode lane)
    ;
    ; in:
    ; - PortableLineAst (or source line to parse on demand in scaffold mode).
    ; - active pipeline selection with loaded package instruction tables.
    ;
    ; stage 0: request guards
    ; if pipeline not set or package not loaded -> runtime error
    ; if input payload invalid -> bad request
    ;
    ; stage 1: obtain instruction candidate set
    ; if input is source line:
    ;   tokenize + parse internally to PortableLineAst
    ; if AST line_kind != instruction:
    ;   return STATUS_OK with zero output bytes (no-op line)
    ;
    ; stage 2: resolve encode tables/program
    ; tabl_key = (mnemonic, operand shape, owner id)
    ; candidate programs from package with owner precedence:
    ;   dialect(TABL) -> cpu(TABL) -> family(TABL)
    ; if no candidates -> deterministic runtime error "OPC_NO_MATCH"
    ;
    ; stage 3: candidate evaluation loop
    ; for each candidate program in deterministic order:
    ;   evaluate operand predicates and expression widths
    ;   apply bank/direct-page assumptions from active CPU profile
    ;   execute TABL VM bytecode (generic opthread::vm opcodes):
    ;     OP_EMIT_U8=0x01 (emit literal opcode/data byte)
    ;     OP_EMIT_OPERAND=0x02 (emit encoded operand i)
    ;     OP_END=0xFF (finish)
    ;   canonical builder pattern is:
    ;     [OP_EMIT_U8, opcode, OP_EMIT_OPERAND, 0, ..., OP_END]
    ;   reject candidate on invalid/truncated program or operand index mismatch
    ; select first successful candidate
    ; if none succeed -> emit deterministic diagnostics per best failure class
    ;
    ; stage 4: emit output payload
    ; write encoded machine bytes to output buffer
    ; optionally append relocation/fixup metadata for pass1 unresolved symbols
    ; set CB_OUTPUT_LEN to emitted byte count (+ metadata size when present)
    ; clear CB_LAST_ERROR_LEN
    ; set STATUS_OK
    ;
    ; stage 5: deterministic failures from opcode paths
    ; missing/invalid TABL programs -> runtime error namespace "OPC_*"
    ; VM invalid opcode / truncated program / bad operand index -> "OPC_*"
    ; unresolved expression policy violations -> runtime error namespace "OPC_*"
    ; malformed request shapes -> bad request namespace "OTR_BAD_REQ"
    jsr set_unimplemented_runtime_error
    rts

handle_last_error:
    lda #C.STATUS_OK
    ldy #0
    jsr set_status
    lda D.control_block + C.CB_LAST_ERROR_LEN_LO
    sta D.control_block + C.CB_OUTPUT_LEN_LO
    lda D.control_block + C.CB_LAST_ERROR_LEN_HI
    sta D.control_block + C.CB_OUTPUT_LEN_HI
    rts

set_unimplemented_runtime_error:
    lda #C.UNIMPL_ERROR_LEN
    jsr set_runtime_error_len
    rts

set_runtime_error_len:
    tax
    lda #C.STATUS_RUNTIME_ERROR
    ldy #0
    jsr set_status
    jsr clear_output_len
    txa
    sta D.control_block + C.CB_LAST_ERROR_LEN_LO
    lda #0
    sta D.control_block + C.CB_LAST_ERROR_LEN_HI
    rts

set_bad_request_len:
    tax
    lda #C.STATUS_BAD_REQUEST
    ldy #0
    jsr set_status
    jsr clear_output_len
    txa
    sta D.control_block + C.CB_LAST_ERROR_LEN_LO
    lda #0
    sta D.control_block + C.CB_LAST_ERROR_LEN_HI
    rts

clear_output_len:
    lda #0
    sta D.control_block + C.CB_OUTPUT_LEN_LO
    sta D.control_block + C.CB_OUTPUT_LEN_HI
    rts

clear_last_error_len:
    lda #0
    sta D.control_block + C.CB_LAST_ERROR_LEN_LO
    sta D.control_block + C.CB_LAST_ERROR_LEN_HI
    rts

set_status:
    sta D.control_block + C.CB_STATUS_LO
    sty D.control_block + C.CB_STATUS_HI
    rts

snapshot_last_status:
    lda D.control_block + C.CB_STATUS_LO
    and #$03
    sta D.last_status_snapshot
    rts

apply_status_color:
    ldx D.last_status_snapshot
    lda D.status_color_table, x
    sta C.C64_BORDERCOLOR

    lda #C.PETSCII_CLR_HOME
    jsr C.C64_CHROUT
    lda #C.PETSCII_O
    jsr C.C64_CHROUT
    lda #C.PETSCII_T
    jsr C.C64_CHROUT
    lda #C.PETSCII_6
    jsr C.C64_CHROUT
    lda #C.PETSCII_5
    jsr C.C64_CHROUT
    lda #C.PETSCII_SPACE
    jsr C.C64_CHROUT
    lda #C.PETSCII_S
    jsr C.C64_CHROUT
    lda #C.PETSCII_C
    jsr C.C64_CHROUT
    lda #C.PETSCII_F
    jsr C.C64_CHROUT
    rts
.endsection

.endmodule
