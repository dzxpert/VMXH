;
; vmx_asm.asm - VMX Anti-Anti-Debug Hypervisor
; x64 assembly routines for VMX operations
;
; Assembled with MASM ml64.exe (WDK 7600)
;

EXTERN VmxExitHandler:PROC
EXTERN VmxResumeFailedHandler:PROC

; VMCS field encodings used by AsmVmxLaunch and AsmVmxExitHandler
VMCS_GUEST_RSP_ENCODING EQU 0681Ch
VMCS_GUEST_RIP_ENCODING EQU 0681Eh

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
VMCS_GUEST_RFLAGS_ENCODING EQU 06820h

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
    ; BUG FIX (Problem H): Also restore Guest RFLAGS via vmread + popfq.
    ; The original code did not restore RFLAGS, leaving Host RFLAGS active
    ; after vmxoff. While most flags are quickly overwritten by subsequent
    ; instructions, special flags (TF, DF, IF) could cause subtle issues.
    ;
    ; Strategy:
    ;   1. vmread Guest RSP/RIP/RFLAGS (must happen before vmxoff)
    ;   2. Push Guest RIP onto Guest stack (so we can 'ret' to it)
    ;   3. vmxoff
    ;   4. Restore all guest GP registers from GUEST_CONTEXT
    ;   5. Push Guest RFLAGS and popfq to restore flags
    ;   6. Set RSP = (Guest RSP - 8), then ret -> Guest RIP
    ; ---------------------------------------------------------------

    ; 1. Read Guest RSP, Guest RIP, and Guest RFLAGS from VMCS
    mov     rcx, VMCS_GUEST_RSP_ENCODING
    vmread  rdx, rcx            ; rdx = Guest RSP

    mov     rcx, VMCS_GUEST_RIP_ENCODING
    vmread  rax, rcx            ; rax = Guest RIP

    mov     rcx, VMCS_GUEST_RFLAGS_ENCODING
    vmread  rcx, rcx            ; rcx = Guest RFLAGS

    ; 2. Push Guest RIP onto the Guest's stack
    sub     rdx, 8
    mov     [rdx], rax          ; Guest stack: [Guest RSP - 8] = Guest RIP

    ; Save adjusted Guest RSP into GUEST_CONTEXT.Rsp slot (offset 0x20)
    ; so we can load it later after restoring all other registers
    mov     [rsp + 020h], rdx

    ; Save Guest RFLAGS into GUEST_CONTEXT.Rax slot (offset 0x00) temporarily
    ; (we'll read it back after restoring other GP regs, before restoring rax)
    ; Actually, use a different approach: save on guest stack too
    sub     rdx, 8
    mov     [rdx], rcx          ; Guest stack: [Guest RSP - 16] = Guest RFLAGS
    mov     [rsp + 020h], rdx   ; Update saved Guest RSP to account for RFLAGS

    ; 3. vmxoff — exit VMX operation
    vmxoff

    ; 4. Restore guest GP registers from GUEST_CONTEXT
    mov     rax, [rsp + 000h]
    mov     rcx, [rsp + 008h]
    mov     rdx, [rsp + 010h]
    mov     rbx, [rsp + 018h]
    ; skip rsp (020h) — we load it last
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

    ; 5. Load Guest RSP (with RFLAGS and RIP on top) and restore RFLAGS
    mov     rsp, [rsp + 020h]   ; switch to guest stack
    popfq                       ; restore Guest RFLAGS (was at [Guest RSP - 16])
    ret                         ; pops Guest RIP, resumes guest execution

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
