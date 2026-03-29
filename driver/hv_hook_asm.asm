;
; hv_hook_asm.asm - VMX Anti-Anti-Debug Hypervisor
; Universal Hook Framework - ASM Generic Dispatcher
;
; Called from thunk stubs with:
;   R10 = Hook ID
;   RCX/RDX/R8/R9 = original function parameters 1-4
;   [RSP]     = caller return address
;   [RSP+28h] = original parameter 5 (after shadow space)
;   [RSP+30h] = original parameter 6
;   [RSP+38h] = original parameter 7
;   [RSP+40h] = original parameter 8
;
; Flow:
;   Phase 1: Save all state, call GenericHookDecide() to get action
;   Phase 2: If not BLOCK, call trampoline (original function) with restored args
;   Phase 3: Post-process (modify retval if needed, log)
;   Return to original caller
;

EXTERN GenericHookDecide:PROC
EXTERN GenericHookPostCall:PROC

.code

AsmGenericHookDispatcher PROC

    ; ===== Prologue =====
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0C0h               ; generous local space (192 bytes)

    ; ===== Save original parameters =====
    mov     [rbp-08h], rcx          ; Arg1
    mov     [rbp-10h], rdx          ; Arg2
    mov     [rbp-18h], r8           ; Arg3
    mov     [rbp-20h], r9           ; Arg4
    mov     [rbp-28h], r10          ; HookId

    ; Save caller return address (above saved RBP and our push)
    mov     rax, [rbp+08h]
    mov     [rbp-30h], rax          ; CallerRetAddr

    ; Copy stack parameters 5-8 from original frame
    ; Original frame layout above our RBP:
    ;   [rbp+00h] = saved RBP
    ;   [rbp+08h] = return address
    ;   [rbp+10h] = shadow space (home for RCX)
    ;   [rbp+18h] = shadow space (home for RDX)
    ;   [rbp+20h] = shadow space (home for R8)
    ;   [rbp+28h] = shadow space (home for R9)
    ;   [rbp+30h] = Arg5
    ;   [rbp+38h] = Arg6
    ;   [rbp+40h] = Arg7
    ;   [rbp+48h] = Arg8
    mov     rax, [rbp+30h]
    mov     [rbp-38h], rax          ; Arg5
    mov     rax, [rbp+38h]
    mov     [rbp-40h], rax          ; Arg6
    mov     rax, [rbp+40h]
    mov     [rbp-48h], rax          ; Arg7
    mov     rax, [rbp+48h]
    mov     [rbp-50h], rax          ; Arg8

    ; ===== Phase 1: Call GenericHookDecide =====
    ; GenericHookDecide(HookIndex, CallerRetAddr, &Decision)
    ; Decision struct at [rbp-90h], 40 bytes (0x28)
    mov     rcx, r10                ; HookIndex
    mov     rdx, [rbp-30h]          ; CallerRetAddr
    lea     r8, [rbp-90h]           ; &Decision
    call    GenericHookDecide

    ; Read Decision.Action (ULONG at offset +0x00)
    mov     eax, dword ptr [rbp-90h]
    mov     [rbp-98h], eax          ; save action for later

    ; Check for BLOCK (action == 2)
    cmp     eax, 2
    je      _do_block

    ; ===== Phase 2: Call trampoline with original args =====

    ; Restore register parameters
    mov     rcx, [rbp-08h]          ; Arg1
    mov     rdx, [rbp-10h]          ; Arg2
    mov     r8,  [rbp-18h]          ; Arg3
    mov     r9,  [rbp-20h]          ; Arg4

    ; Set up stack params for trampoline call (shadow + args 5-8)
    mov     rax, [rbp-38h]          ; Arg5
    mov     [rsp+20h], rax
    mov     rax, [rbp-40h]          ; Arg6
    mov     [rsp+28h], rax
    mov     rax, [rbp-48h]          ; Arg7
    mov     [rsp+30h], rax
    mov     rax, [rbp-50h]          ; Arg8
    mov     [rsp+38h], rax

    ; Load trampoline address from Decision.Trampoline (offset +0x18)
    mov     rax, [rbp-90h+18h]
    test    rax, rax
    jz      _no_trampoline

    ; Call the original function via trampoline
    call    rax

    ; RAX now holds original function's return value
    mov     [rbp-0A0h], rax         ; save original retval

    ; Check if MODIFY_RETVAL (action == 3)
    mov     ecx, [rbp-98h]
    cmp     ecx, 3
    jne     _post_call

    ; Overwrite return value from Decision.NewReturnValue (offset +0x10)
    mov     rax, [rbp-90h+10h]
    mov     [rbp-0A0h], rax

    jmp     _post_call

_do_block:
    ; Load Decision.BlockReturnValue (offset +0x08)
    mov     rax, [rbp-90h+08h]
    mov     [rbp-0A0h], rax         ; this becomes our return value
    jmp     _post_call

_no_trampoline:
    ; Trampoline is NULL - shouldn't happen, return 0
    xor     rax, rax
    mov     [rbp-0A0h], rax

_post_call:
    ; ===== Phase 3: Post-processing (logging) =====
    ; GenericHookPostCall(HookIndex, Action, FinalRetVal, CallerRetAddr, ShouldLog)

    mov     rcx, [rbp-28h]          ; HookIndex
    mov     edx, [rbp-98h]          ; Action
    mov     r8,  [rbp-0A0h]         ; FinalRetVal
    mov     r9,  [rbp-30h]          ; CallerRetAddr

    ; 5th param: ShouldLog - Decision.ShouldLog is at offset +0x20 (BOOLEAN)
    movzx   eax, byte ptr [rbp-90h+20h]
    mov     [rsp+20h], rax

    call    GenericHookPostCall

    ; ===== Epilogue: return final value to original caller =====
    mov     rax, [rbp-0A0h]

    mov     rsp, rbp
    pop     rbp
    ret

AsmGenericHookDispatcher ENDP

END
