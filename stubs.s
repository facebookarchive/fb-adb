        .altmacro
        .macro bin_data sym, file
        .section .rodata
        .global \sym
\sym&:
        .incbin \file
\sym&_end:
        .balign 4
        .global \sym&sz
\sym&sz:
        .int \sym&_end - \sym
.endm

        bin_data arm_stub "stub-arm/adbx.stripped"
        bin_data x86_stub "stub-x86/adbx.stripped"
