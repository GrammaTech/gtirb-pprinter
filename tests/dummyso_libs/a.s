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
