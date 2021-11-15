        .file   "b.s"
        .text
        .section        .rodata
.message:
        .string "b() invoked!\n"
        .text
        .globl  b
        .type   b, @function
b:
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
