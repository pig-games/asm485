; Mutable runtime state and scaffold-owned sample payloads.

.module op465.data
    .pub

.section data_vm, align=1
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
active_source_name_ptr_lo:
    .byte 0
active_source_name_ptr_hi:
    .byte 0
active_source_name_len:
    .byte 0

set_pipeline_payload:
    ; "m6502\0"
    .byte $6d, $36, $35, $30, $32, $00

sample_opcpu_header:
    ; OPCP + version 0x0001 + endian marker 0x1234 (little-endian)
    .byte $4f, $50, $43, $50, $01, $00, $34, $12

sample_source_filename:
    ; "MAIN.ASM"
    .byte $4d, $41, $49, $4e, $2e, $41, $53, $4d
sample_source_line:
    ; "LDA #$10"
    .byte $4c, $44, $41, $20, $23, $24, $31, $30

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

status_color_table:
    ; STATUS_OK / STATUS_BAD_CONTROL_BLOCK / STATUS_BAD_REQUEST / STATUS_RUNTIME_ERROR
    .byte $05, $07, $08, $02
.endsection

.endmodule
