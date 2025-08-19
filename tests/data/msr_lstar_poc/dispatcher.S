#include "constants.h"

.section .text

/* syscall_new will be used by intercept.c */
.global syscall_new

/* Two macros to SAVE or CONTINUE (restore) context */
.macro SAVE
    swapgs
    mov %rsp,%gs:OLD_RSP
    mov %gs:KERNEL_STACK,%rsp
    sti

    sub $0x50,%rsp
    mov %rdi,0x40(%rsp)
    mov %rsi,0x38(%rsp)
    mov %rdx,0x30(%rsp)
    mov %rax,0x20(%rsp)
    mov %r8,0x18(%rsp)
    mov %r9,0x10(%rsp)
    mov %r10,0x8(%rsp)
    mov %r11,(%rsp)
    mov %rax,0x48(%rsp)
    mov %rcx,0x50(%rsp)
.endm

.macro CONTINUE
    cli
    mov 0x50(%rsp),%rcx
    mov (%rsp),%r11
    mov 0x8(%rsp),%r10
    mov 0x10(%rsp),%r9
    mov 0x18(%rsp),%r8
    mov 0x20(%rsp),%rax
    mov 0x30(%rsp),%rdx
    mov 0x38(%rsp),%rsi
    mov 0x40(%rsp),%rdi
    mov %gs:OLD_RSP,%rsp
    jmp *syscall_after_swapgs
.endm

/* This becomes the new entry point for syscall() */
syscall_new:
    /* The syscall number is stored in %rax. syscall 0xf = sigreturn */
    cmp $0x0f, %rax
    je do_sigreturn

    /* Fallthrough to the original system call implementation, no need to do
     * saving and restoring here. */
    jmp *syscall_orig

/* This is simply a stub that saves, calls our C function, and restores +
 * continues execution. */
do_sigreturn:
    SAVE
    call do_c_sigreturn
    CONTINUE

