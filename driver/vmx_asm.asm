;
; vmx_asm.asm - VMX Anti-Anti-Debug Hypervisor
; x64 assembly routines for VMX operations
;
; Assembled with MASM ml64.exe (WDK 7600)
;

EXTERN VmxExitHandler:PROC
EXTERN VmxResumeFailedHandler:PROC

; VMCS field encodings — defined before AsmVmxExitHandler (which uses them first).
; AsmVmxLaunch also uses VMCS_GUEST_RSP_ENCODING and VMCS_GUEST_RIP_ENCODING.

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
VMCS_EXIT_REASON_ENCODING EQU 04402h
VMCS_GUEST_RIP_ENCODING   EQU 0681Eh
VMCS_GUEST_RSP_ENCODING   EQU 0681Ch
VMCS_GUEST_RFLAGS_ENCODING EQU 06820h
VMCS_GUEST_CS_ENCODING    EQU 00802h
VMCS_GUEST_SS_ENCODING    EQU 00804h

AsmVmxExitHandler PROC

    ;
    ; Save all Guest GP registers FIRST, before calling any function.
    ;
    ; CRITICAL: On VM-Exit, hardware loads Host RSP/RIP but Guest GP registers
    ; are still live in the CPU registers. We MUST save them to the stack-based
    ; GUEST_CONTEXT structure BEFORE calling any C function (including DbgPrintEx).
    ; The x64 calling convention allows callees to clobber RAX/RCX/RDX/R8-R11,
    ; which would destroy the Guest register values and corrupt Guest state on
    ; VMRESUME.
    ;
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
    ; ---------------------------------------------------------------
    ; VmxExitHandler returned FALSE: exit VMX and resume as non-root.
    ;
    ; We're on the Host stack with the saved GUEST_CONTEXT at [rsp].
    ; VmxAdvanceGuestRip() has already advanced Guest RIP past VMCALL.
    ;
    ; Strategy (IRETQ-based, inspired by NBP Trampoline):
    ;   1. vmread Guest RSP/RIP/RFLAGS/CS/SS (must happen before vmxoff)
    ;   2. vmxoff — exit VMX operation
    ;   3. Build IRETQ frame on Guest stack
    ;   4. Restore all Guest GP registers from GUEST_CONTEXT
    ;   5. Switch to Guest stack and IRETQ
    ;
    ; IRETQ atomically restores CS:RIP + SS:RSP + RFLAGS, which is more
    ; canonical than the previous popfq+ret approach (which didn't restore
    ; CS/SS segments). In Blue Pill mode Host CS == Guest CS, but using
    ; IRETQ is future-proof for independent Host GDT scenarios.
    ; ---------------------------------------------------------------

    ; ---- Phase 1: vmread Guest state (before vmxoff!) ----
    ; Allocate 40 bytes (5 qwords) below GUEST_CONTEXT for temporaries.
    ; Stack layout: [rsp+0..0x27] = temp, [rsp+0x28..0xA7] = GUEST_CONTEXT
    sub     rsp, 28h

    mov     rcx, VMCS_GUEST_RSP_ENCODING
    vmread  rax, rcx
    mov     [rsp + 00h], rax                ; Guest RSP

    mov     rcx, VMCS_GUEST_RIP_ENCODING
    vmread  rax, rcx
    mov     [rsp + 08h], rax                ; Guest RIP

    mov     rcx, VMCS_GUEST_RFLAGS_ENCODING
    vmread  rax, rcx
    mov     [rsp + 10h], rax                ; Guest RFLAGS

    mov     rcx, VMCS_GUEST_CS_ENCODING
    vmread  rax, rcx
    mov     [rsp + 18h], rax                ; Guest CS

    mov     rcx, VMCS_GUEST_SS_ENCODING
    vmread  rax, rcx
    mov     [rsp + 20h], rax                ; Guest SS

    ; ---- Phase 2: vmxoff ----
    vmxoff

    ; ---- Phase 3: Build IRETQ frame on Guest stack ----
    ; IRETQ pops: [RSP+0]=RIP, [RSP+8]=CS, [RSP+16]=RFLAGS, [RSP+24]=RSP, [RSP+32]=SS
    mov     rax, [rsp + 00h]                ; Guest RSP
    sub     rax, 28h                        ; 5 * 8 bytes for IRETQ frame

    mov     rcx, [rsp + 08h]               ; Guest RIP
    mov     [rax + 00h], rcx                ; IRETQ frame: RIP

    mov     rcx, [rsp + 18h]               ; Guest CS
    mov     [rax + 08h], rcx                ; IRETQ frame: CS

    mov     rcx, [rsp + 10h]               ; Guest RFLAGS
    mov     [rax + 10h], rcx                ; IRETQ frame: RFLAGS

    mov     rcx, [rsp + 00h]               ; Guest RSP (original, pre-frame)
    mov     [rax + 18h], rcx                ; IRETQ frame: RSP

    mov     rcx, [rsp + 20h]               ; Guest SS
    mov     [rax + 20h], rcx                ; IRETQ frame: SS

    ; Save IRETQ frame base into temp area for later use
    mov     [rsp + 00h], rax

    ; ---- Phase 4: Restore Guest GP registers ----
    ; GUEST_CONTEXT is at [rsp + 0x28] (offset by the 40-byte temp area)
    mov     rax, [rsp + 028h]
    mov     rcx, [rsp + 030h]
    mov     rdx, [rsp + 038h]
    mov     rbx, [rsp + 040h]
    ; skip rsp (048h) — loaded last as stack switch
    mov     rbp, [rsp + 050h]
    mov     rsi, [rsp + 058h]
    mov     rdi, [rsp + 060h]
    mov     r8,  [rsp + 068h]
    mov     r9,  [rsp + 070h]
    mov     r10, [rsp + 078h]
    mov     r11, [rsp + 080h]
    mov     r12, [rsp + 088h]
    mov     r13, [rsp + 090h]
    mov     r14, [rsp + 098h]
    mov     r15, [rsp + 0A0h]

    ; ---- Phase 5: Switch to Guest stack and IRETQ ----
    mov     rsp, [rsp + 00h]               ; RSP → IRETQ frame on Guest stack
    iretq                                   ; Atomically restore CS:RIP + SS:RSP + RFLAGS

VmxResumeFailed:
    ; vmresume failed - this is a critical error.
    ; Read the VM-instruction error from VMCS before vmxoff destroys it.
    ;
    ; RCX = VMCS_VM_INSTRUCTION_ERROR encoding (0x4400)
    ; RAX = error number (returned by vmread)
    mov     rcx, 04400h
    vmread  rax, rcx            ; rax = VM-instruction error number

    ; Save error number for C call (rcx = first arg in x64 ABI)
    mov     rcx, rax

    ; We're on the host stack. Call the C handler to log the error.
    ; The GUEST_CONTEXT is still at the base of our frame.
    sub     rsp, 28h            ; shadow space for x64 ABI
    call    VmxResumeFailedHandler
    add     rsp, 28h

    ; Now exit VMX and halt
    vmxoff
    cli
    hlt
    jmp     VmxResumeFailed     ; infinite halt loop as safety net

AsmVmxExitHandler ENDP

; =========================================================================
;  VMLAUNCH Wrapper for Blue Pill
;  UCHAR AsmVmxLaunch(VOID)
;  Returns: 0 = success (now in guest), 1 = vmlaunch failed
;
;  Before executing vmlaunch, writes:
;    VMCS Guest RSP = current RSP
;    VMCS Guest RIP = address of _LaunchSuccess label
;  On successful vmlaunch, CPU resumes in guest mode at _LaunchSuccess,
;  which returns 0 to the caller.
; =========================================================================

AsmVmxLaunch PROC
    ; Save non-volatile registers (callee-saved per x64 ABI)
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    ; Write Guest RSP = current RSP (after pushes, this is the guest stack)
    mov     rdx, rsp
    mov     rcx, VMCS_GUEST_RSP_ENCODING
    vmwrite rcx, rdx
    jc      _LaunchFail     ; CF=1: vmwrite failed (not in VMX operation)
    jz      _LaunchFail     ; ZF=1: vmwrite failed (invalid field)

    ; Write Guest RIP = address of _LaunchSuccess label
    ; On successful vmlaunch, guest starts executing at this address
    lea     rdx, [_LaunchSuccess]
    mov     rcx, VMCS_GUEST_RIP_ENCODING
    vmwrite rcx, rdx
    jc      _LaunchFail
    jz      _LaunchFail

    vmlaunch

    ; If we reach here, vmlaunch failed (CF=1 or ZF=1 on error)
_LaunchFail:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    mov     rax, 1          ; Return failure
    ret

_LaunchSuccess:
    ; CPU enters guest mode and resumes here.
    ; RSP was restored by vmlaunch from VMCS Guest RSP, so our
    ; pushed registers are still on the stack.
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    xor     rax, rax        ; Return 0 = success
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
;  void AsmVmxVmcall(ULONG64 HypercallValue)
;  RCX = value to pass in RAX to hypervisor
; =========================================================================

AsmVmxVmcall PROC
    mov     rax, rcx
    vmcall
    ret
AsmVmxVmcall ENDP

END
