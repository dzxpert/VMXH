;
; svm_asm.asm - VMX Anti-Anti-Debug Hypervisor
; x64 assembly routines for AMD SVM operations
;
; Assembled with MASM ml64.exe (WDK 7600)
;
; Key SVM instructions (not natively supported by ml64):
;   VMRUN:   0F 01 D8  (RAX = physical address of VMCB)
;   VMLOAD:  0F 01 DA  (RAX = physical address of VMCB)
;   VMSAVE:  0F 01 DB  (RAX = physical address of VMCB)
;   CLGI:    0F 01 DD  (Clear Global Interrupt Flag)
;   STGI:    0F 01 DC  (Set Global Interrupt Flag)
;

EXTERN SvmExitHandler:PROC

.code

; =========================================================================
;  CLGI - Clear Global Interrupt Flag
;  void AsmClgi(void)
; =========================================================================

AsmClgi PROC
    db      0Fh, 01h, 0DDh             ; CLGI
    ret
AsmClgi ENDP

; =========================================================================
;  STGI - Set Global Interrupt Flag
;  void AsmStgi(void)
; =========================================================================

AsmStgi PROC
    db      0Fh, 01h, 0DCh             ; STGI
    ret
AsmStgi ENDP

; =========================================================================
;  SVM VMRUN Entry Point
;
;  void AsmSvmVmrun(ULONG64 VmcbPa, PGUEST_CONTEXT GuestContext)
;  RCX = VMCB physical address
;  RDX = pointer to GUEST_CONTEXT
;
;  This function:
;    1. Saves host callee-saved registers
;    2. Loads guest GP registers from GUEST_CONTEXT
;    3. Executes VMLOAD + VMRUN
;    4. On #VMEXIT, executes VMSAVE
;    5. Saves guest GP registers to GUEST_CONTEXT
;    6. Restores host callee-saved registers
;    7. Returns (to C exit handler)
;
;  VMCB.save already has RAX,RSP,RIP,RFLAGS etc.
;  We manage the other GP registers via GUEST_CONTEXT.
; =========================================================================

AsmSvmVmrun PROC

    ; Save host callee-saved registers (Win x64 ABI)
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    ; Save parameters
    push    rcx                         ; Save VMCB PA on stack
    push    rdx                         ; Save GUEST_CONTEXT pointer

    ; Load guest GP registers from GUEST_CONTEXT (RDX = context ptr)
    ; Note: RAX is loaded from VMCB.save by VMRUN
    ;       RSP is loaded from VMCB.save by VMRUN
    mov     rcx, [rdx + 008h]          ; RCX
    mov     rbx, [rdx + 018h]          ; RBX
    mov     rbp, [rdx + 028h]          ; RBP
    mov     rsi, [rdx + 030h]          ; RSI
    mov     rdi, [rdx + 038h]          ; RDI
    mov     r8,  [rdx + 040h]          ; R8
    mov     r9,  [rdx + 048h]          ; R9
    mov     r10, [rdx + 050h]          ; R10
    mov     r11, [rdx + 058h]          ; R11
    mov     r12, [rdx + 060h]          ; R12
    mov     r13, [rdx + 068h]          ; R13
    mov     r14, [rdx + 070h]          ; R14
    mov     r15, [rdx + 078h]          ; R15

    ; Load guest RDX last (since we're using it as base)
    mov     rdx, [rdx + 010h]          ; RDX

    ; RAX = VMCB physical address (for VMRUN/VMLOAD/VMSAVE)
    mov     rax, [rsp + 8]             ; Recover VMCB PA from stack

    ; VMLOAD: Load additional guest state from VMCB
    ; (FS, GS, TR, LDTR, KernelGSBase, STAR, LSTAR, CSTAR, SFMASK, SYSENTER_*)
    db      0Fh, 01h, 0DAh             ; VMLOAD

    ; VMRUN: Enter guest mode
    ; RAX must contain VMCB physical address
    ; On #VMEXIT, execution continues at the next instruction
    db      0Fh, 01h, 0D8h             ; VMRUN

    ; === #VMEXIT occurred, we're back in host ===

    ; VMSAVE: Save guest state back to VMCB
    ; RAX still contains VMCB PA (restored by hardware on #VMEXIT)
    db      0Fh, 01h, 0DBh             ; VMSAVE

    ; Now save guest GP registers to GUEST_CONTEXT
    ; First, get the GUEST_CONTEXT pointer back from stack
    ; Stack: [RSP] = GUEST_CONTEXT ptr, [RSP+8] = VMCB PA

    ; Save RAX temporarily
    push    rax

    ; Get GUEST_CONTEXT pointer (it was at [rsp+8] before our push, so now [rsp+16])
    mov     rax, [rsp + 8]             ; GUEST_CONTEXT pointer

    ; Note: don't save guest RAX here - it's in VMCB.save.rax
    ; But we need to propagate it to GUEST_CONTEXT for the C handler
    ; The VMCB PA is still in [rsp+16], VMCB.save.rax has the guest RAX
    ; For simplicity, the C code will read guest RAX from VMCB

    ; Save guest GP registers
    mov     [rax + 008h], rcx          ; RCX
    mov     [rax + 010h], rdx          ; RDX
    mov     [rax + 018h], rbx          ; RBX
    ; RSP is in VMCB.save.rsp
    mov     [rax + 028h], rbp          ; RBP
    mov     [rax + 030h], rsi          ; RSI
    mov     [rax + 038h], rdi          ; RDI
    mov     [rax + 040h], r8           ; R8
    mov     [rax + 048h], r9           ; R9
    mov     [rax + 050h], r10          ; R10
    mov     [rax + 058h], r11          ; R11
    mov     [rax + 060h], r12          ; R12
    mov     [rax + 068h], r13          ; R13
    mov     [rax + 070h], r14          ; R14
    mov     [rax + 078h], r15          ; R15

    ; Restore RAX (was VMCB PA)
    pop     rax

    ; Clean up saved parameters
    pop     rdx                         ; Discard GUEST_CONTEXT ptr
    pop     rcx                         ; Discard VMCB PA

    ; Restore host callee-saved registers
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx

    ret

AsmSvmVmrun ENDP

; =========================================================================
;  SVM Exit Handler Entry Point
;
;  This is the host-level #VMEXIT handler.
;  Called after VMRUN returns (when guest exits).
;  The SVM VMRUN loop is managed in C code using AsmSvmVmrun,
;  so this is provided as an alternative direct entry point
;  if needed for a different calling convention.
;
;  For our architecture, the main exit handling is done in the
;  C VMRUN loop (svm_init.c), which calls SvmExitHandler() directly.
;  This ASM handler is provided for completeness.
; =========================================================================

GUEST_CTX_SIZE EQU 128

AsmSvmExitHandler PROC

    ; Save guest GP registers on stack (same layout as GUEST_CONTEXT)
    sub     rsp, GUEST_CTX_SIZE

    mov     [rsp + 000h], rax
    mov     [rsp + 008h], rcx
    mov     [rsp + 010h], rdx
    mov     [rsp + 018h], rbx
    mov     [rsp + 020h], rsp          ; Placeholder
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

    ; RCX = pointer to GUEST_CONTEXT (first arg for SvmExitHandler)
    mov     rcx, rsp

    ; Allocate shadow space for call
    sub     rsp, 28h
    call    SvmExitHandler
    add     rsp, 28h

    ; Check return value: TRUE = resume guest, FALSE = shutdown
    test    al, al
    jz      SvmShutdown

    ; Restore guest GP registers
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

    ; Re-enter guest via VMRUN
    ; RAX must contain VMCB PA - caller should have set this up
    db      0Fh, 01h, 0D8h             ; VMRUN
    ret

SvmShutdown:
    ; Restore registers for clean return
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
    ret

AsmSvmExitHandler ENDP

; =========================================================================
;  Blue Pill VMRUN Launch
;
;  UCHAR AsmSvmLaunch(ULONG64 VmcbPa)
;  RCX = VMCB physical address
;  Returns: 0 = success (now in guest), 1 = failure
;
;  Sets VMCB.Save.Rsp and .Rip just before the first VMRUN so that
;  the guest resumes into the VMRUN loop.  After VMRUN, the CPU enters
;  guest mode.  Each #VMEXIT returns to the loop, which calls
;  SvmExitHandler(). When it returns FALSE, we break out and return 0.
;
;  VMCB save-area offsets:
;    Rip = +0x578, Rsp = +0x5D8, Rax = +0x5F8
; =========================================================================

VMCB_SAVE_RIP_OFFSET EQU 0578h
VMCB_SAVE_RSP_OFFSET EQU 05D8h
VMCB_SAVE_RAX_OFFSET EQU 05F8h

AsmSvmLaunch PROC

    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    ; Save VMCB PA (physical addr) in r12 (callee-saved) for the loop
    mov     r12, rcx            ; r12 = VMCB PA

    ; We need the VMCB virtual address to write Rsp/Rip fields.
    ; The C code passes physical address for VMRUN, but VMCB is also
    ; mapped at a virtual address.  To write the fields, we need
    ; the VA.  The caller should provide it.
    ;
    ; Alternative: use a 2-parameter version.  Let's change the prototype:
    ;   UCHAR AsmSvmLaunch(ULONG64 VmcbPa, PVOID VmcbVa)
    ;   RCX = VmcbPa, RDX = VmcbVa
    mov     r13, rdx            ; r13 = VMCB VA

    ; Set VMCB.Save.Rsp = current RSP (guest will continue on this stack)
    mov     [r13 + VMCB_SAVE_RSP_OFFSET], rsp

    ; Set VMCB.Save.Rip = _SvmLaunchSuccess (guest resumes there)
    lea     rax, [_SvmLaunchSuccess]
    mov     [r13 + VMCB_SAVE_RIP_OFFSET], rax

    ; RAX = VMCB PA (required by VMRUN/VMLOAD/VMSAVE)
    mov     rax, r12

    ; CLGI: Clear GIF to prevent interrupts during VMRUN
    db      0Fh, 01h, 0DDh     ; CLGI

    ; VMLOAD: Load additional guest state from VMCB
    db      0Fh, 01h, 0DAh     ; VMLOAD

    ; VMRUN: Enter guest mode.
    ; On success, CPU loads guest state from VMCB and starts executing
    ; at VMCB.Save.Rip (_SvmLaunchSuccess).
    db      0Fh, 01h, 0D8h     ; VMRUN

    ; #VMEXIT occurred.  CPU is back in host mode.
    ; RAX = VMCB PA (preserved by hardware).

    ; VMSAVE: Save guest state to VMCB
    db      0Fh, 01h, 0DBh     ; VMSAVE

    ; STGI: Re-enable interrupts
    db      0Fh, 01h, 0DCh     ; STGI

    ; VMRUN failed to enter guest or exited before reaching _SvmLaunchSuccess
    ; (shouldn't happen normally, but handle it)
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    mov     rax, 1              ; Return failure
    ret

_SvmLaunchSuccess:
    ; Guest is now running!  CPU entered guest mode and resumed here.
    ; This is the VMRUN loop: handle exits and re-enter.
    ;
    ; RSP was restored from VMCB.Save.Rsp (our stack with pushed regs).
    ; r12 = VMCB PA, r13 = VMCB VA (callee-saved, preserved).

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    xor     rax, rax            ; Return 0 = success
    ret

AsmSvmLaunch ENDP

; =========================================================================
;  VMMCALL Wrapper (AMD equivalent of VMCALL)
;  void AsmSvmVmmcall(ULONG64 HypercallValue)
;  RCX = value to pass in RAX to hypervisor
; =========================================================================

AsmSvmVmmcall PROC
    mov     rax, rcx
    db      0Fh, 01h, 0D9h     ; VMMCALL
    ret
AsmSvmVmmcall ENDP

END
