; Host integration hooks for loading source and .opcpu package bytes.
;
; Replace these routine bodies with real C64 I/O paths (IEC/KERNAL/REU/etc).

.module op465.hooks
    .cpu 6502
    .use op465.contract as C
    .use op465.data as D
    .pub

.section code_hooks, align=1
host_hook_load_opcpu_package:
    ; Required outputs:
    ; - D.control_block + CB_INPUT_PTR_* points to package bytes.
    ; - D.current_input_len contains package payload length (v1 scaffold is < 256).
    lda #<D.sample_opcpu_header
    sta D.control_block + C.CB_INPUT_PTR_LO
    lda #>D.sample_opcpu_header
    sta D.control_block + C.CB_INPUT_PTR_HI
    lda #C.SAMPLE_PACKAGE_LEN
    sta D.current_input_len
    rts

host_hook_open_input_file:
    ; Required behavior:
    ; - Select/open source file.
    ; - Initialize any host-owned line cursor state.
    lda #<D.sample_source_filename
    sta D.active_source_name_ptr_lo
    lda #>D.sample_source_filename
    sta D.active_source_name_ptr_hi
    lda #C.SAMPLE_SOURCE_NAME_LEN
    sta D.active_source_name_len
    rts

host_hook_next_source_line:
    ; Required outputs:
    ; - D.control_block + CB_INPUT_PTR_* points to current source line bytes.
    ; - D.current_input_len is line length; set to 0 for EOF.
    lda #<D.sample_source_line
    sta D.control_block + C.CB_INPUT_PTR_LO
    lda #>D.sample_source_line
    sta D.control_block + C.CB_INPUT_PTR_HI
    lda #C.SAMPLE_SOURCE_LINE_LEN
    sta D.current_input_len
    rts
.endsection

.endmodule
