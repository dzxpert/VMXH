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
;  Blue Pill VMRUN Launch (full VMRUN loop, host-state-safe)
;
;  UCHAR AsmSvmLaunch(ULONG64 VmcbPa, PVOID VmcbVa, ULONG64 HostVmcbPa)
;    RCX = VMCB physical address                (Guest VMCB, for VMRUN)
;    RDX = VMCB virtual address                 (for writing Save.Rip/Save.Rsp)
;     R8 = Host VMCB physical address           (for VMSAVE/VMLOAD host)
;    Returns:
;      0 = shutdown requested by SvmExitHandler (normal unload)
;      1 = failure (reserved; not currently produced)
;
;  VMRUN loop (AMD APM Vol.2 §15.5 "Saving Host State" + §15.20):
;
;    Startup (once):
;        VMSAVE [HostVmcbPa]        ; capture real host FS/GS/TR/LDTR.base,
;                                   ; KernelGsBase, STAR, LSTAR, CSTAR,
;                                   ; SFMASK, SYSENTER_{CS,ESP,EIP}
;        VMCB.Save.Rsp = current host RSP
;        VMCB.Save.Rip = _SvmLaunchGuest
;
;    Per-iteration (reverse order of what the previous, broken, version did):
;        CLGI
;        VMLOAD [VmcbPa]            ; load GUEST FS/GS/TR/... into CPU
;        VMRUN  [VmcbPa]            ; enter guest; hardware auto-saves
;                                   ; the *subset* host state listed in APM
;                                   ; §15.5.1 to MSR_VM_HSAVE_PA's page.
;        --- #VMEXIT: HSAVE-managed host state (CR3/RFLAGS/RAX/RSP/RIP/
;            CS/SS/DS/ES) is auto-restored by the CPU, but FS/GS/TR/LDTR
;            base, KernelGsBase, and the SYSCALL MSRs still hold GUEST
;            values — Windows would instantly BSOD if we ran C code now. ---
;        VMSAVE [VmcbPa]            ; snapshot guest FS/GS/TR/... back into
;                                   ; VMCB.Save so they survive until next
;                                   ; VMRUN.  MUST be done before VMLOAD
;                                   ; host, otherwise guest state is lost.
;        VMLOAD [HostVmcbPa]        ; reload host FS/GS/TR/... — now safe
;                                   ; to run C code / touch KPCR / etc.
;        STGI
;        save guest GP regs into on-stack GUEST_CONTEXT
;        CALL SvmExitHandler(GUEST_CONTEXT*)
;        AL==0 → break loop, return 0
;        AL!=0 → reload guest GP regs from GUEST_CONTEXT and loop
;
;  Why we need THREE VMCBs (guest + HSAVE + HostVmcb):
;    - Guest VMCB: described by AMD APM.  Passed to VMRUN.
;    - HSAVE area (at MSR_VM_HSAVE_PA): CPU-internal, only touched by
;      CPU on VMRUN/VMEXIT.  Holds a subset of host state.
;    - Host VMCB: software-managed target of VMSAVE/VMLOAD host.  Holds
;      the remainder of host state that the CPU does NOT auto-save.
;    Using the same page for HSAVE and Host VMCB is unsafe because the
;    next VMRUN's hardware save would clobber what VMSAVE placed there.
;
;  Anchor storage: VmcbPa / VmcbVa / HostVmcbPa all live in dedicated
;  stack slots and are re-read from the stack after every VMEXIT, because
;  VMRUN does NOT save/restore host GP registers — the loop puts guest
;  GP values into all 15 writable GP regs (including r12/r13/r14/r15)
;  before VMRUN, and the only way to keep the anchors alive across the
;  guest execution window is on the stack.
;
;  VMCB Save-area offsets (AMD APM Vol.2 Appendix B):
;    Rip = +0x578, Rsp = +0x5D8, Rax = +0x5F8
; =========================================================================

VMCB_SAVE_RIP_OFFSET EQU 0578h
VMCB_SAVE_RSP_OFFSET EQU 05D8h
VMCB_SAVE_RAX_OFFSET EQU 05F8h

;
; On-stack GUEST_CONTEXT layout — must match the C struct GUEST_CONTEXT
; in vmx.h (reused by SVM side).  16 × 8 = 128 bytes.
;
GCTX_RAX EQU 000h
GCTX_RCX EQU 008h
GCTX_RDX EQU 010h
GCTX_RBX EQU 018h
GCTX_RSP EQU 020h
GCTX_RBP EQU 028h
GCTX_RSI EQU 030h
GCTX_RDI EQU 038h
GCTX_R8  EQU 040h
GCTX_R9  EQU 048h
GCTX_R10 EQU 050h
GCTX_R11 EQU 058h
GCTX_R12 EQU 060h
GCTX_R13 EQU 068h
GCTX_R14 EQU 070h
GCTX_R15 EQU 078h
GCTX_SIZE EQU 080h             ; 128 bytes

;
; Full stack frame layout during the VMRUN loop (low → high addresses):
;   [rsp + 0x00 .. 0x1F]  — shadow space for the SvmExitHandler CALL
;   [rsp + 0x20 .. 0x9F]  — GUEST_CONTEXT (128 bytes)
;   [rsp + 0xA0 .. 0xA7]  — VmcbPa anchor
;   [rsp + 0xA8 .. 0xAF]  — VmcbVa anchor
;   [rsp + 0xB0 .. 0xB7]  — HostVmcbPa anchor
;   [rsp + 0xB8 .. 0xBF]  — 16-byte-alignment padding
;   [rsp + 0xC0 .. ]      — callee-saved regs from prolog
;
; Total reserved = 0x20 + 0x80 + 0x18 + 0x08 (pad) = 0xC0 bytes.
;

AsmSvmLaunch PROC FRAME
    push    rbx
    .pushreg rbx
    push    rbp
    .pushreg rbp
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15

    sub     rsp, 0C0h
    .allocstack 0C0h
    .endprolog

    ; Save anchors on the stack.
    mov     [rsp + 0A0h], rcx            ; VmcbPa
    mov     [rsp + 0A8h], rdx            ; VmcbVa
    mov     [rsp + 0B0h], r8             ; HostVmcbPa

    ;
    ; STEP 1 — capture real host FS/GS/TR/LDTR.base + SYSCALL MSRs into
    ; the Host VMCB so every subsequent VMEXIT can restore them.
    ;
    ; VMSAVE uses RAX as the operand (physical address of target VMCB).
    ;
    mov     rax, r8                      ; RAX = HostVmcbPa
    db      0Fh, 01h, 0DBh               ; VMSAVE

    ;
    ; STEP 2 — first-time Guest VMCB setup: point Save.Rsp/Rip so that
    ; after the FIRST successful VMRUN, the guest immediately "returns"
    ; through _SvmLaunchGuest to the DPC caller.  Subsequent VMEXITs
    ; come back to the instruction after VMRUN in _SvmVmrunLoop, NOT
    ; here.
    ;
    mov     rax, rsp
    mov     [rdx + VMCB_SAVE_RSP_OFFSET], rax
    lea     rax, [_SvmLaunchGuest]
    mov     [rdx + VMCB_SAVE_RIP_OFFSET], rax

    ;
    ; STEP 3 — zero the on-stack GUEST_CONTEXT.  Guest GP regs for the
    ; first iteration are irrelevant because the guest enters at
    ; _SvmLaunchGuest which only runs epilog + ret.
    ;
    xor     rax, rax
    mov     [rsp + 020h + GCTX_RAX], rax
    mov     [rsp + 020h + GCTX_RCX], rax
    mov     [rsp + 020h + GCTX_RDX], rax
    mov     [rsp + 020h + GCTX_RBX], rax
    mov     [rsp + 020h + GCTX_RSP], rax
    mov     [rsp + 020h + GCTX_RBP], rax
    mov     [rsp + 020h + GCTX_RSI], rax
    mov     [rsp + 020h + GCTX_RDI], rax
    mov     [rsp + 020h + GCTX_R8],  rax
    mov     [rsp + 020h + GCTX_R9],  rax
    mov     [rsp + 020h + GCTX_R10], rax
    mov     [rsp + 020h + GCTX_R11], rax
    mov     [rsp + 020h + GCTX_R12], rax
    mov     [rsp + 020h + GCTX_R13], rax
    mov     [rsp + 020h + GCTX_R14], rax
    mov     [rsp + 020h + GCTX_R15], rax

_SvmVmrunLoop:
    ;
    ; STEP 4 — load guest GP regs from GUEST_CONTEXT.  Anchors stay on
    ; the stack.  Loading ALL 15 regs before VMRUN is mandatory because
    ; VMRUN does not auto-save host GP values.
    ;
    mov     rcx, [rsp + 020h + GCTX_RCX]
    mov     rdx, [rsp + 020h + GCTX_RDX]
    mov     rbx, [rsp + 020h + GCTX_RBX]
    mov     rbp, [rsp + 020h + GCTX_RBP]
    mov     rsi, [rsp + 020h + GCTX_RSI]
    mov     rdi, [rsp + 020h + GCTX_RDI]
    mov     r8,  [rsp + 020h + GCTX_R8]
    mov     r9,  [rsp + 020h + GCTX_R9]
    mov     r10, [rsp + 020h + GCTX_R10]
    mov     r11, [rsp + 020h + GCTX_R11]
    mov     r12, [rsp + 020h + GCTX_R12]
    mov     r13, [rsp + 020h + GCTX_R13]
    mov     r14, [rsp + 020h + GCTX_R14]
    mov     r15, [rsp + 020h + GCTX_R15]

    ; RAX = Guest VMCB PA (for VMLOAD/VMRUN).  Guest RAX lives in VMCB.Save.Rax.
    mov     rax, [rsp + 0A0h]

    ;
    ; STEP 5 — enter guest:  CLGI → VMLOAD guest → VMRUN.
    ;
    ;   CLGI disables GIF so no NMI/SMI/interrupt can sneak in between
    ;   the VMLOAD (which puts guest state into CPU) and the VMRUN
    ;   (which enters guest mode); an interrupt firing in that window
    ;   would service the interrupt with guest segment bases, BSOD.
    ;
    ;   VMLOAD copies guest FS/GS/TR/LDTR.base + SYSCALL MSRs from
    ;   VMCB.Save into the CPU.
    ;
    ;   VMRUN atomically saves host CR3/RFLAGS/RAX/RSP/RIP/CS/SS/DS/ES
    ;   to the HSAVE area and loads the guest's full state.
    ;
    db      0Fh, 01h, 0DDh     ; CLGI
    db      0Fh, 01h, 0DAh     ; VMLOAD
    db      0Fh, 01h, 0D8h     ; VMRUN

    ;
    ; === #VMEXIT — we are back in host mode ===
    ;   Hardware auto-restored: CR3, RFLAGS, RAX (=VMCB PA),
    ;       RSP, RIP, CS, SS, DS, ES.
    ;   Hardware did NOT restore: FS, GS, TR, LDTR, KernelGsBase,
    ;       STAR, LSTAR, CSTAR, SFMASK, SYSENTER_* — they STILL hold
    ;       GUEST values here.
    ;   Therefore we CANNOT run any C code or touch [gs:...] until
    ;   we have executed VMLOAD host below.
    ;
    ; NB: GIF is cleared on VMEXIT per AMD APM §15.17.  We keep it
    ; cleared across VMSAVE guest + VMLOAD host to preserve atomicity,
    ; then STGI before calling C.
    ;

    ;
    ; STEP 6 — snapshot guest extra-state (FS/GS/TR/LDTR base, SYSCALL
    ; MSRs) back into the Guest VMCB so we don't lose guest changes to
    ; these fields across the host excursion.  RAX still holds Guest
    ; VMCB PA from the VMRUN, so this is a simple VMSAVE.
    ;
    db      0Fh, 01h, 0DBh     ; VMSAVE  [rax]  (guest VMCB)

    ;
    ; STEP 7 — reload real host extra-state.  After this, [gs:KPCR],
    ; FS:<TEB>, SYSCALL, SYSENTER, TR (TSS), LDTR are all back to their
    ; pre-VMRUN host values — C code is safe.
    ;
    mov     rax, [rsp + 0B0h]  ; RAX = HostVmcbPa
    db      0Fh, 01h, 0DAh     ; VMLOAD [rax]  (host VMCB)

    ;
    ; STEP 8 — re-enable GIF and save guest GP regs for the C handler.
    ;
    db      0Fh, 01h, 0DCh     ; STGI

    mov     [rsp + 020h + GCTX_RCX], rcx
    mov     [rsp + 020h + GCTX_RDX], rdx
    mov     [rsp + 020h + GCTX_RBX], rbx
    mov     [rsp + 020h + GCTX_RBP], rbp
    mov     [rsp + 020h + GCTX_RSI], rsi
    mov     [rsp + 020h + GCTX_RDI], rdi
    mov     [rsp + 020h + GCTX_R8],  r8
    mov     [rsp + 020h + GCTX_R9],  r9
    mov     [rsp + 020h + GCTX_R10], r10
    mov     [rsp + 020h + GCTX_R11], r11
    mov     [rsp + 020h + GCTX_R12], r12
    mov     [rsp + 020h + GCTX_R13], r13
    mov     [rsp + 020h + GCTX_R14], r14
    mov     [rsp + 020h + GCTX_R15], r15

    ;
    ; STEP 9 — dispatch to C handler.  Guest RAX/RSP live in VMCB.Save
    ; and are synced into / out of GuestContext by SvmExitHandler.
    ;
    lea     rcx, [rsp + 020h]
    call    SvmExitHandler

    ; AL == 0 → shutdown requested → break loop.
    test    al, al
    jz      _SvmShutdown

    ; Otherwise reload regs and re-enter guest.
    jmp     _SvmVmrunLoop

_SvmShutdown:
    ;
    ; Normal shutdown: handler returned FALSE (nonce-authenticated
    ; VMMCALL shutdown or fatal escalation).  SVM is still enabled on
    ; this CPU; SvmTerminateDpcRoutine calls SvmDisableOnCpu() after
    ; we return to clear EFER.SVME + zero HSAVE_PA.
    ;
    ; Host extra-state is already loaded (we're here *after* an
    ; iteration's VMLOAD host), so popping the frame and returning is
    ; safe.
    ;
    add     rsp, 0C0h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    xor     rax, rax
    ret

_SvmLaunchGuest:
    ;
    ; First-VMRUN landing pad.  The CPU enters here (in guest mode,
    ; but executing host code — we're virtualising ourselves) with RSP
    ; equal to what we wrote into VMCB.Save.Rsp before the first VMRUN,
    ; i.e. the top of AsmSvmLaunch's stack frame.  Unwind and "return"
    ; to the DPC caller as if AsmSvmLaunch had completed normally.
    ;
    ; All host extra-state was set up by VMLOAD [VmcbPa] before the
    ; first VMRUN — which loaded Guest VMCB FS/GS/TR/... .  But those
    ; fields were populated by SvmInitVmcb() from the REAL host values
    ; of this CPU (__readmsr(MSR_FS_BASE)/... and AsmGet{Fs,Gs,Tr}()),
    ; so semantically they ARE the host values.  Therefore the Windows
    ; kernel can keep running normally.
    ;
    add     rsp, 0C0h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    xor     rax, rax
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

; =========================================================================
;  VMMCALL Wrapper (2-argument form — used for nonce-authenticated calls)
;  void AsmSvmVmmcall2(ULONG64 HypercallValue /*RCX*/, ULONG64 Arg1 /*RDX*/)
;
;  Sets:
;    RAX <- HypercallValue (from RCX)
;    RCX <- Arg1           (from RDX)
;  Used for VMCALL_MAGIC_SHUTDOWN where Arg1 carries the per-boot nonce.
; =========================================================================

AsmSvmVmmcall2 PROC
    mov     rax, rcx
    mov     rcx, rdx
    db      0Fh, 01h, 0D9h     ; VMMCALL
    ret
AsmSvmVmmcall2 ENDP

END
