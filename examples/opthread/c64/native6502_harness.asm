; opThread native 6502 harness scaffold for C64 / VICE.
; This is a host-side harness skeleton, not a full VM implementation yet.

.module main
    .cpu 6502

ENTRY_ORD_INIT               .const 0
ENTRY_ORD_LOAD_PACKAGE       .const 1
ENTRY_ORD_SET_PIPELINE       .const 2
ENTRY_ORD_TOKENIZE_LINE      .const 3
ENTRY_ORD_PARSE_LINE         .const 4
ENTRY_ORD_ENCODE_INSTRUCTION .const 5
ENTRY_ORD_LAST_ERROR         .const 6

STATUS_OK                .const 0
STATUS_BAD_CONTROL_BLOCK .const 1
STATUS_BAD_REQUEST       .const 2
STATUS_RUNTIME_ERROR     .const 3

CB_MAGIC_0           .const 0
CB_MAGIC_1           .const 1
CB_MAGIC_2           .const 2
CB_MAGIC_3           .const 3
CB_ABI_VERSION_LO    .const 4
CB_ABI_VERSION_HI    .const 5
CB_STRUCT_SIZE_LO    .const 6
CB_STRUCT_SIZE_HI    .const 7
CB_CAP_FLAGS_LO      .const 8
CB_CAP_FLAGS_HI      .const 9
CB_STATUS_LO         .const 10
CB_STATUS_HI         .const 11
CB_REQUEST_ID_LO     .const 12
CB_REQUEST_ID_HI     .const 13
CB_INPUT_PTR_LO      .const 16
CB_INPUT_PTR_HI      .const 17
CB_INPUT_LEN_LO      .const 18
CB_INPUT_LEN_HI      .const 19
CB_OUTPUT_LEN_LO     .const 22
CB_OUTPUT_LEN_HI     .const 23
CB_LAST_ERROR_LEN_LO .const 30
CB_LAST_ERROR_LEN_HI .const 31
CB_SIZE              .const 32

CAP_EXT_TLV     .const 1
CAP_STRUCT_META .const 2
CAP_ENUM_META   .const 4
CAP_FLAGS_V1    .const CAP_EXT_TLV | CAP_STRUCT_META | CAP_ENUM_META

C64_BGCOLOR     .const $D021
C64_BORDERCOLOR .const $D020
C64_CHROUT      .const $FFD2

PETSCII_CLR_HOME .const $93
PETSCII_O        .const $4f
PETSCII_T        .const $54
PETSCII_6        .const $36
PETSCII_5        .const $35
PETSCII_SPACE    .const $20
PETSCII_S        .const $53
PETSCII_C        .const $43
PETSCII_F        .const $46

ZP_INPUT_PTR_LO .const $fb
ZP_INPUT_PTR_HI .const $fc

OPCPU_HEADER_LEN      .const 8
SAMPLE_PACKAGE_LEN    .const 8
OTR_BAD_REQ_ERROR_LEN .const 11
OPC_BAD_HEADER_LEN    .const 11

; PETSCII "m6502\0"
SET_PIPELINE_PAYLOAD_LEN .const 6
SET_PIPELINE_MIN_LEN     .const 2
SET_PIPELINE_CPU_LEN     .const 5
OTR_NO_PACKAGE_ERROR_LEN .const 10
OTR_BAD_PIPELINE_LEN     .const 11
UNIMPL_ERROR_LEN         .const 12

.region c64mem, $0801, $2000, align=1

.section basic, align=1
; 10 SYS 2062
; code starts immediately after BASIC line terminator/footer.
basic_stub:
    .byte $0c, $08
    .byte $0a, $00
    .byte $9e, $20
    .byte $32, $30, $36, $32
    .byte $00
    .byte $00, $00
.endsection

.section code, align=1
start:
    sei
    cld

    lda #$06
    sta C64_BGCOLOR
    lda #$0e
    sta C64_BORDERCOLOR

    jsr entry_init
    jsr entry_load_package
    jsr entry_set_pipeline
    jsr snapshot_last_status
    jsr entry_last_error
    jsr apply_status_color

idle_forever:
    jmp idle_forever

entry_init:
    lda #ENTRY_ORD_INIT
    sta current_entry
    lda #0
    sta current_input_len
    jsr prepare_request
    jsr handle_init
    rts

entry_load_package:
    lda #ENTRY_ORD_LOAD_PACKAGE
    sta current_entry
    lda #<sample_opcpu_header
    sta control_block + CB_INPUT_PTR_LO
    lda #>sample_opcpu_header
    sta control_block + CB_INPUT_PTR_HI
    lda #SAMPLE_PACKAGE_LEN
    sta current_input_len
    jsr prepare_request
    jsr handle_load_package
    rts

entry_set_pipeline:
    lda #ENTRY_ORD_SET_PIPELINE
    sta current_entry
    lda #<set_pipeline_payload
    sta control_block + CB_INPUT_PTR_LO
    lda #>set_pipeline_payload
    sta control_block + CB_INPUT_PTR_HI
    lda #SET_PIPELINE_PAYLOAD_LEN
    sta current_input_len
    jsr prepare_request
    jsr handle_set_pipeline
    rts

entry_tokenize_line:
    lda #ENTRY_ORD_TOKENIZE_LINE
    sta current_entry
    lda #0
    sta current_input_len
    jsr prepare_request
    jsr handle_tokenize
    rts

entry_parse_line:
    lda #ENTRY_ORD_PARSE_LINE
    sta current_entry
    lda #0
    sta current_input_len
    jsr prepare_request
    jsr handle_parse
    rts

entry_encode_instruction:
    lda #ENTRY_ORD_ENCODE_INSTRUCTION
    sta current_entry
    lda #0
    sta current_input_len
    jsr prepare_request
    jsr handle_encode
    rts

entry_last_error:
    lda #ENTRY_ORD_LAST_ERROR
    sta current_entry
    lda #0
    sta current_input_len
    jsr prepare_request
    jsr handle_last_error
    rts

prepare_request:
    ; request id++
    clc
    lda control_block + CB_REQUEST_ID_LO
    adc #1
    sta control_block + CB_REQUEST_ID_LO
    lda control_block + CB_REQUEST_ID_HI
    adc #0
    sta control_block + CB_REQUEST_ID_HI

    ; input length
    lda current_input_len
    sta control_block + CB_INPUT_LEN_LO
    lda #0
    sta control_block + CB_INPUT_LEN_HI
    rts

handle_init:
    lda #$4f ; O
    sta control_block + CB_MAGIC_0
    lda #$54 ; T
    sta control_block + CB_MAGIC_1
    lda #$36 ; 6
    sta control_block + CB_MAGIC_2
    lda #$35 ; 5
    sta control_block + CB_MAGIC_3

    lda #$01
    sta control_block + CB_ABI_VERSION_LO
    lda #$00
    sta control_block + CB_ABI_VERSION_HI

    lda #CB_SIZE
    sta control_block + CB_STRUCT_SIZE_LO
    lda #$00
    sta control_block + CB_STRUCT_SIZE_HI

    lda #CAP_FLAGS_V1
    sta control_block + CB_CAP_FLAGS_LO
    lda #$00
    sta control_block + CB_CAP_FLAGS_HI

    lda #0
    sta package_is_loaded
    sta pipeline_is_set

    lda #STATUS_OK
    ldy #0
    jsr set_status
    jsr clear_output_len
    jsr clear_last_error_len
    rts

handle_load_package:
    lda control_block + CB_INPUT_PTR_LO
    sta ZP_INPUT_PTR_LO
    sta loaded_pkg_ptr_lo
    lda control_block + CB_INPUT_PTR_HI
    sta ZP_INPUT_PTR_HI
    sta loaded_pkg_ptr_hi
    lda control_block + CB_INPUT_LEN_LO
    sta loaded_pkg_len_lo
    lda control_block + CB_INPUT_LEN_HI
    sta loaded_pkg_len_hi

    ; bad request if input pointer is null.
    lda ZP_INPUT_PTR_LO
    ora ZP_INPUT_PTR_HI
    cmp #1
    lda #0
    adc #0
    eor #1
    sta load_pkg_ptr_zero_flag

    ; bad request if input length is shorter than required header size.
    lda loaded_pkg_len_lo
    cmp #OPCPU_HEADER_LEN
    lda #0
    adc #0
    sta load_pkg_len_lo_ge_header_flag

    lda loaded_pkg_len_hi
    cmp #1
    lda #0
    adc #0
    sta load_pkg_len_hi_nonzero_flag

    lda load_pkg_len_lo_ge_header_flag
    ora load_pkg_len_hi_nonzero_flag
    eor #1
    sta load_pkg_len_short_flag

    lda load_pkg_ptr_zero_flag
    ora load_pkg_len_short_flag
    cmp #1
    lda #0
    adc #0
    sta load_pkg_bad_request_flag

    ; accumulate OPCP magic mismatch.
    ldy #0
    lda (ZP_INPUT_PTR_LO), y
    eor #$4f ; O
    sta load_pkg_magic_mismatch_accum
    iny
    lda (ZP_INPUT_PTR_LO), y
    eor #$50 ; P
    ora load_pkg_magic_mismatch_accum
    sta load_pkg_magic_mismatch_accum
    iny
    lda (ZP_INPUT_PTR_LO), y
    eor #$43 ; C
    ora load_pkg_magic_mismatch_accum
    sta load_pkg_magic_mismatch_accum
    iny
    lda (ZP_INPUT_PTR_LO), y
    eor #$50 ; P
    ora load_pkg_magic_mismatch_accum
    sta load_pkg_magic_mismatch_accum
    lda load_pkg_magic_mismatch_accum
    cmp #1
    lda #0
    adc #0
    sta load_pkg_magic_mismatch_flag

    ; accumulate package version mismatch (expect 0x0001 little-endian).
    iny
    lda (ZP_INPUT_PTR_LO), y
    eor #$01
    sta load_pkg_version_mismatch_accum
    iny
    lda (ZP_INPUT_PTR_LO), y
    eor #$00
    ora load_pkg_version_mismatch_accum
    sta load_pkg_version_mismatch_accum
    lda load_pkg_version_mismatch_accum
    cmp #1
    lda #0
    adc #0
    sta load_pkg_version_mismatch_flag

    ; accumulate package endian marker mismatch (expect 0x1234 little-endian).
    iny
    lda (ZP_INPUT_PTR_LO), y
    eor #$34
    sta load_pkg_endian_mismatch_accum
    iny
    lda (ZP_INPUT_PTR_LO), y
    eor #$12
    ora load_pkg_endian_mismatch_accum
    sta load_pkg_endian_mismatch_accum
    lda load_pkg_endian_mismatch_accum
    cmp #1
    lda #0
    adc #0
    sta load_pkg_endian_mismatch_flag

    lda load_pkg_magic_mismatch_flag
    ora load_pkg_version_mismatch_flag
    ora load_pkg_endian_mismatch_flag
    cmp #1
    lda #0
    adc #0
    sta load_pkg_header_mismatch_flag

    ; status selector index:
    ; 0 -> ok
    ; 1 -> bad request
    ; 2 -> runtime OPC error
    ; 3 -> bad request (bad request has priority)
    lda load_pkg_header_mismatch_flag
    asl a
    clc
    adc load_pkg_bad_request_flag
    tax

    lda load_pkg_loaded_flag_table, x
    sta package_is_loaded
    lda #0
    sta pipeline_is_set

    lda load_pkg_status_table, x
    ldy #0
    jsr set_status
    jsr clear_output_len
    lda load_pkg_error_len_table, x
    sta control_block + CB_LAST_ERROR_LEN_LO
    lda #0
    sta control_block + CB_LAST_ERROR_LEN_HI
    rts

handle_set_pipeline:
    lda package_is_loaded
    bne set_pipeline_check_ptr
    lda #OTR_NO_PACKAGE_ERROR_LEN
    jsr set_runtime_error_len
    rts

set_pipeline_check_ptr:
    lda control_block + CB_INPUT_PTR_LO
    sta ZP_INPUT_PTR_LO
    lda control_block + CB_INPUT_PTR_HI
    sta ZP_INPUT_PTR_HI
    lda ZP_INPUT_PTR_LO
    ora ZP_INPUT_PTR_HI
    bne set_pipeline_check_len
    lda #OTR_BAD_REQ_ERROR_LEN
    jsr set_bad_request_len
    rts

set_pipeline_check_len:
    lda control_block + CB_INPUT_LEN_HI
    bne set_pipeline_bad_request
    lda control_block + CB_INPUT_LEN_LO
    cmp #SET_PIPELINE_MIN_LEN
    bcs set_pipeline_find_separator
set_pipeline_bad_request:
    lda #OTR_BAD_REQ_ERROR_LEN
    jsr set_bad_request_len
    rts

set_pipeline_find_separator:
    ldy #0
set_pipeline_find_separator_loop:
    cpy control_block + CB_INPUT_LEN_LO
    beq set_pipeline_bad_request
    lda (ZP_INPUT_PTR_LO), y
    beq set_pipeline_separator_found
    iny
    bne set_pipeline_find_separator_loop
    beq set_pipeline_bad_request

set_pipeline_separator_found:
    ; y contains cpu_id byte length.
    cpy #0
    beq set_pipeline_bad_request
    cpy #SET_PIPELINE_CPU_LEN
    bne set_pipeline_unsupported

    ldy #0
set_pipeline_compare_cpu_loop:
    lda (ZP_INPUT_PTR_LO), y
    cmp set_pipeline_payload, y
    bne set_pipeline_unsupported
    iny
    cpy #SET_PIPELINE_CPU_LEN
    bne set_pipeline_compare_cpu_loop

    ; v1 scaffold supports cpu_id "m6502" with no dialect suffix.
    lda control_block + CB_INPUT_LEN_LO
    cmp #SET_PIPELINE_PAYLOAD_LEN
    bne set_pipeline_unsupported

    lda #1
    sta pipeline_is_set
    lda #STATUS_OK
    ldy #0
    jsr set_status
    jsr clear_output_len
    jsr clear_last_error_len
    rts

set_pipeline_unsupported:
    lda #OTR_BAD_PIPELINE_LEN
    jsr set_runtime_error_len
    rts

handle_tokenize:
    jsr set_unimplemented_runtime_error
    rts

handle_parse:
    jsr set_unimplemented_runtime_error
    rts

handle_encode:
    jsr set_unimplemented_runtime_error
    rts

handle_last_error:
    lda #STATUS_OK
    ldy #0
    jsr set_status
    lda control_block + CB_LAST_ERROR_LEN_LO
    sta control_block + CB_OUTPUT_LEN_LO
    lda control_block + CB_LAST_ERROR_LEN_HI
    sta control_block + CB_OUTPUT_LEN_HI
    rts

set_unimplemented_runtime_error:
    lda #UNIMPL_ERROR_LEN
    jsr set_runtime_error_len
    rts

set_runtime_error_len:
    tax
    lda #STATUS_RUNTIME_ERROR
    ldy #0
    jsr set_status
    jsr clear_output_len
    txa
    sta control_block + CB_LAST_ERROR_LEN_LO
    lda #0
    sta control_block + CB_LAST_ERROR_LEN_HI
    rts

set_bad_request_len:
    tax
    lda #STATUS_BAD_REQUEST
    ldy #0
    jsr set_status
    jsr clear_output_len
    txa
    sta control_block + CB_LAST_ERROR_LEN_LO
    lda #0
    sta control_block + CB_LAST_ERROR_LEN_HI
    rts

clear_output_len:
    lda #0
    sta control_block + CB_OUTPUT_LEN_LO
    sta control_block + CB_OUTPUT_LEN_HI
    rts

clear_last_error_len:
    lda #0
    sta control_block + CB_LAST_ERROR_LEN_LO
    sta control_block + CB_LAST_ERROR_LEN_HI
    rts

set_status:
    ; in: A=lo, Y=hi
    sta control_block + CB_STATUS_LO
    sty control_block + CB_STATUS_HI
    rts

snapshot_last_status:
    lda control_block + CB_STATUS_LO
    and #$03
    sta last_status_snapshot
    rts

apply_status_color:
    ldx last_status_snapshot
    lda status_color_table, x
    sta C64_BORDERCOLOR

    ; Print signature via KERNAL CHROUT using PETSCII bytes.
    lda #PETSCII_CLR_HOME
    jsr C64_CHROUT
    lda #PETSCII_O
    jsr C64_CHROUT
    lda #PETSCII_T
    jsr C64_CHROUT
    lda #PETSCII_6
    jsr C64_CHROUT
    lda #PETSCII_5
    jsr C64_CHROUT
    lda #PETSCII_SPACE
    jsr C64_CHROUT
    lda #PETSCII_S
    jsr C64_CHROUT
    lda #PETSCII_C
    jsr C64_CHROUT
    lda #PETSCII_F
    jsr C64_CHROUT
    rts
.endsection

.section data, align=1
control_block:
    .byte $00, $00, $00, $00, $00, $00, $00, $00
    .byte $00, $00, $00, $00, $00, $00, $00, $00
    .byte $00, $00, $00, $00, $00, $00, $00, $00
    .byte $00, $00, $00, $00, $00, $00, $00, $00

current_entry:
    .byte 0
current_input_len:
    .byte 0
last_status_snapshot:
    .byte 0
package_is_loaded:
    .byte 0
pipeline_is_set:
    .byte 0
loaded_pkg_ptr_lo:
    .byte 0
loaded_pkg_ptr_hi:
    .byte 0
loaded_pkg_len_lo:
    .byte 0
loaded_pkg_len_hi:
    .byte 0
load_pkg_ptr_zero_flag:
    .byte 0
load_pkg_len_lo_ge_header_flag:
    .byte 0
load_pkg_len_hi_nonzero_flag:
    .byte 0
load_pkg_len_short_flag:
    .byte 0
load_pkg_bad_request_flag:
    .byte 0
load_pkg_magic_mismatch_accum:
    .byte 0
load_pkg_magic_mismatch_flag:
    .byte 0
load_pkg_version_mismatch_accum:
    .byte 0
load_pkg_version_mismatch_flag:
    .byte 0
load_pkg_endian_mismatch_accum:
    .byte 0
load_pkg_endian_mismatch_flag:
    .byte 0
load_pkg_header_mismatch_flag:
    .byte 0

set_pipeline_payload:
    .byte $6d, $36, $35, $30, $32, $00

sample_opcpu_header:
    ; OPCP + version 0x0001 + endian marker 0x1234 (little-endian)
    .byte $4f, $50, $43, $50, $01, $00, $34, $12

otr_bad_req_error:
    ; "OTR_BAD_REQ"
    .byte $4f, $54, $52, $5f, $42, $41, $44, $5f, $52, $45, $51
otr_no_package_error:
    ; "OTR_NO_PKG"
    .byte $4f, $54, $52, $5f, $4e, $4f, $5f, $50, $4b, $47
otr_bad_pipeline_error:
    ; "OTR_BAD_CPU"
    .byte $4f, $54, $52, $5f, $42, $41, $44, $5f, $43, $50, $55
opc_bad_header_error:
    ; "OPC_BAD_HDR"
    .byte $4f, $50, $43, $5f, $42, $41, $44, $5f, $48, $44, $52
unimpl_error_ascii:
    ; "NOT_IMPL_OTR"
    .byte $4e, $4f, $54, $5f, $49, $4d, $50, $4c, $5f, $4f, $54, $52

load_pkg_status_table:
    ; index 0..3: ok, bad-req, runtime-opc, bad-req
    .byte STATUS_OK, STATUS_BAD_REQUEST, STATUS_RUNTIME_ERROR, STATUS_BAD_REQUEST
load_pkg_error_len_table:
    ; index 0..3: ok, OTR, OPC, OTR
    .byte 0, OTR_BAD_REQ_ERROR_LEN, OPC_BAD_HEADER_LEN, OTR_BAD_REQ_ERROR_LEN
load_pkg_loaded_flag_table:
    ; index 0..3: loaded-on-success only
    .byte 1, 0, 0, 0

status_color_table:
    ; STATUS_OK / STATUS_BAD_CONTROL_BLOCK / STATUS_BAD_REQUEST / STATUS_RUNTIME_ERROR
    .byte $05, $07, $08, $02
.endsection

.pack in c64mem : basic, code, data

.output "build/opthread-native6502-harness.prg", format=prg, contiguous=false, sections=basic,code,data
.mapfile "build/opthread-native6502-harness.map", symbols=all

.endmodule
