;
; vmx_asm.asm - VMX Anti-Anti-Debug Hypervisor
; x64 assembly routines for VMX operations
;
; Assembled with MASM ml64.exe (WDK 7600)
;

EXTERN VmxExitHandler:PROC

.code

; =========================================================================
;  Segment Register Accessors
; =========================================================================

AsmGetCs PROC
    xor     rax, rax
    mov     ax, cs
    ret
AsmGetCs ENDP

AsmGetSs PROC
    xor     rax, rax
    mov     ax, ss
    ret
AsmGetSs ENDP

AsmGetDs PROC
    xor     rax, rax
    mov     ax, ds
    ret
AsmGetDs ENDP

AsmGetEs PROC
    xor     rax, rax
    mov     ax, es
    ret
AsmGetEs ENDP

AsmGetFs PROC
    xor     rax, rax
    mov     ax, fs
    ret
AsmGetFs ENDP

AsmGetGs PROC
    xor     rax, rax
    mov     ax, gs
    ret
AsmGetGs ENDP

AsmGetTr PROC
    xor     rax, rax
    str     eax
    ret
AsmGetTr ENDP

AsmGetLdtr PROC
    xor     rax, rax
    sldt    eax
    ret
AsmGetLdtr ENDP

; =========================================================================
;  Descriptor Table Register Accessors
;  Use sub rsp instead of LOCAL (ml64 LOCAL requires FRAME)
; =========================================================================

AsmGetGdtBase PROC
    sub     rsp, 16
    sgdt    [rsp]
    mov     rax, QWORD PTR [rsp + 2]
    add     rsp, 16
    ret
AsmGetGdtBase ENDP

AsmGetGdtLimit PROC
    sub     rsp, 16
    sgdt    [rsp]
    xor     rax, rax
    mov     ax, WORD PTR [rsp]
    add     rsp, 16
    ret
AsmGetGdtLimit ENDP

AsmGetIdtBase PROC
    sub     rsp, 16
    sidt    [rsp]
    mov     rax, QWORD PTR [rsp + 2]
    add     rsp, 16
    ret
AsmGetIdtBase ENDP

AsmGetIdtLimit PROC
    sub     rsp, 16
    sidt    [rsp]
    xor     rax, rax
    mov     ax, WORD PTR [rsp]
    add     rsp, 16
    ret
AsmGetIdtLimit ENDP

; =========================================================================
;  RFLAGS Accessor
; =========================================================================

AsmGetRflags PROC
    pushfq
    pop     rax
    ret
AsmGetRflags ENDP

; =========================================================================
;  INVEPT Wrapper
;  UCHAR AsmVmxInvept(ULONG Type, PINVEPT_DESCRIPTOR Desc)
;  RCX = Type, RDX = pointer to INVEPT_DESCRIPTOR
;  Returns: 0 = success, 1 = fail
;
;  invept encoding: 66 0F 38 80 /r (mem128)
;  We encode: 66 0F 38 80 0A  = invept rcx, [rdx]
; =========================================================================

AsmVmxInvept PROC
    db      066h, 00Fh, 038h, 080h, 00Ah
    jz      InveptFail
    jc      InveptFail
    xor     rax, rax
    ret
InveptFail:
    mov     rax, 1
    ret
AsmVmxInvept ENDP

; =========================================================================
;  INVVPID Wrapper
;  UCHAR AsmVmxInvvpid(ULONG Type, PINVVPID_DESCRIPTOR Desc)
;
;  invvpid encoding: 66 0F 38 81 /r (mem128)
;  We encode: 66 0F 38 81 0A  = invvpid rcx, [rdx]
; =========================================================================

AsmVmxInvvpid PROC
    db      066h, 00Fh, 038h, 081h, 00Ah
    jz      InvvpidFail
    jc      InvvpidFail
    xor     rax, rax
    ret
InvvpidFail:
    mov     rax, 1
    ret
AsmVmxInvvpid ENDP

; =========================================================================
;  VM-Exit Handler Entry Point
; =========================================================================

GUEST_CTX_SIZE EQU 128

AsmVmxExitHandler PROC

    sub     rsp, GUEST_CTX_SIZE

    mov     [rsp + 000h], rax
    mov     [rsp + 008h], rcx
    mov     [rsp + 010h], rdx
    mov     [rsp + 018h], rbx
    mov     [rsp + 020h], rsp
    mov     [rsp + 028h], rbp
    mov     [rsp + 030h], rsi
    mov     [rsp + 038h], rdi
    mov     [rsp + 040h], r8
    mov     [rsp + 048h], r9
    mov     [rsp + 050h], r10
    mov     [rsp + 058h], r11
    mov     [rsp + 060h], r12
    mov     [rsp + 068h], r13
    mov     [rsp + 070h], r14
    mov     [rsp + 078h], r15

    mov     rcx, rsp
    sub     rsp, 28h

    call    VmxExitHandler

    add     rsp, 28h

    test    al, al
    jz      VmxShutdown

    mov     rax, [rsp + 000h]
    mov     rcx, [rsp + 008h]
    mov     rdx, [rsp + 010h]
    mov     rbx, [rsp + 018h]
    mov     rbp, [rsp + 028h]
    mov     rsi, [rsp + 030h]
    mov     rdi, [rsp + 038h]
    mov     r8,  [rsp + 040h]
    mov     r9,  [rsp + 048h]
    mov     r10, [rsp + 050h]
    mov     r11, [rsp + 058h]
    mov     r12, [rsp + 060h]
    mov     r13, [rsp + 068h]
    mov     r14, [rsp + 070h]
    mov     r15, [rsp + 078h]

    add     rsp, GUEST_CTX_SIZE

    vmresume

    jmp     VmxResumeFailed

VmxShutdown:
    mov     rax, [rsp + 000h]
    mov     rcx, [rsp + 008h]
    mov     rdx, [rsp + 010h]
    mov     rbx, [rsp + 018h]
    mov     rbp, [rsp + 028h]
    mov     rsi, [rsp + 030h]
    mov     rdi, [rsp + 038h]
    mov     r8,  [rsp + 040h]
    mov     r9,  [rsp + 048h]
    mov     r10, [rsp + 050h]
    mov     r11, [rsp + 058h]
    mov     r12, [rsp + 060h]
    mov     r13, [rsp + 068h]
    mov     r14, [rsp + 070h]
    mov     r15, [rsp + 078h]

    add     rsp, GUEST_CTX_SIZE

    vmxoff
    ret

VmxResumeFailed:
    int 3
    ret

AsmVmxExitHandler ENDP

; =========================================================================
;  VMLAUNCH Wrapper
; =========================================================================

AsmVmxLaunch PROC
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    vmlaunch

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx

    ret
AsmVmxLaunch ENDP

; =========================================================================
;  Save Host State
;  void AsmSaveHostState(PGUEST_CONTEXT Context)
;  RCX = pointer to GUEST_CONTEXT
; =========================================================================

AsmSaveHostState PROC
    mov     [rcx + 000h], rax
    mov     [rcx + 008h], rcx
    mov     [rcx + 010h], rdx
    mov     [rcx + 018h], rbx
    mov     [rcx + 020h], rsp
    mov     [rcx + 028h], rbp
    mov     [rcx + 030h], rsi
    mov     [rcx + 038h], rdi
    mov     [rcx + 040h], r8
    mov     [rcx + 048h], r9
    mov     [rcx + 050h], r10
    mov     [rcx + 058h], r11
    mov     [rcx + 060h], r12
    mov     [rcx + 068h], r13
    mov     [rcx + 070h], r14
    mov     [rcx + 078h], r15
    ret
AsmSaveHostState ENDP

; =========================================================================
;  Restore Guest State
; =========================================================================

AsmRestoreGuestState PROC
    mov     rax, [rcx + 000h]
    mov     rdx, [rcx + 010h]
    mov     rbx, [rcx + 018h]
    mov     rbp, [rcx + 028h]
    mov     rsi, [rcx + 030h]
    mov     rdi, [rcx + 038h]
    mov     r8,  [rcx + 040h]
    mov     r9,  [rcx + 048h]
    mov     r10, [rcx + 050h]
    mov     r11, [rcx + 058h]
    mov     r12, [rcx + 060h]
    mov     r13, [rcx + 068h]
    mov     r14, [rcx + 070h]
    mov     r15, [rcx + 078h]
    mov     rcx, [rcx + 008h]
    ret
AsmRestoreGuestState ENDP

; =========================================================================
;  XSETBV Wrapper
;  void AsmXsetbv(ULONG Index, ULONG64 Value)
;  RCX = index, RDX = value
; =========================================================================

AsmXsetbv PROC
    mov     rax, rdx
    shr     rdx, 32
    ; xsetbv: 0F 01 D1
    db      00Fh, 001h, 0D1h
    ret
AsmXsetbv ENDP

; =========================================================================
;  VMCALL Wrapper
; =========================================================================

AsmVmxVmcall PROC
    vmcall
    ret
AsmVmxVmcall ENDP

END
