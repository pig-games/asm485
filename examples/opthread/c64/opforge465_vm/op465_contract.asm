; Frozen v1 control-block contract and fixed status/ordinal constants.

.module op465.contract
    .pub
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

OPCPU_HEADER_LEN       .const 8
SAMPLE_PACKAGE_LEN     .const 8
SAMPLE_SOURCE_LINE_LEN .const 8
SAMPLE_SOURCE_NAME_LEN .const 8

SET_PIPELINE_PAYLOAD_LEN .const 6
SET_PIPELINE_MIN_LEN     .const 2
SET_PIPELINE_CPU_LEN     .const 5

OTR_BAD_REQ_ERROR_LEN    .const 11
OTR_NO_PACKAGE_ERROR_LEN .const 10
OTR_BAD_PIPELINE_LEN     .const 11
OPC_BAD_HEADER_LEN       .const 11
UNIMPL_ERROR_LEN         .const 12
.endmodule
