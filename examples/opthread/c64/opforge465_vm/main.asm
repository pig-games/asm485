; opForge465 C64 native VM project scaffold (root module).

.module op465.main
    .cpu 6502
    .use op465.vmcore as VM

.region c64mem, $0801, $4000, align=1

.section basic_main, align=1
; 10 SYS 2062
basic_stub:
    .byte $0c, $08
    .byte $0a, $00
    .byte $9e, $20
    .byte $32, $30, $36, $32
    .byte $00
    .byte $00, $00
.endsection

.section code_main, align=1
start:
    sei
    cld
    jsr VM.vm_bootstrap_demo
idle_forever:
    jmp idle_forever
.endsection

.pack in c64mem : basic_main,code_main,code_vmcore,code_hooks,data_vm

.output "build/opforge465-c64-native-bootstrap.prg", format=prg, contiguous=false, sections=basic_main,code_main,code_vmcore,code_hooks,data_vm
.mapfile "build/opforge465-c64-native-bootstrap.map", symbols=all

.endmodule
