; This file contains code for the function a(),
; which prints a simple message to stdout.
; Note that this makes a direct system call rather
; than, say, calling puts(), because the
; testcase using this does not include CRT code, and
; we're not linking against libc.

        .file   "a.s"
        .text
        .section        .rodata
.message:
        .string "a() invoked!\n"
        .text
        .globl  a
        .type   a, @function
a:
        pushq   %rbp
        movq    %rsp, %rbp
        leaq    .message(%rip), %rsi
        mov     $1, %rax
        mov     $1, %rdi
        mov     $13, %rdx
        syscall
        nop
        popq    %rbp
        ret
