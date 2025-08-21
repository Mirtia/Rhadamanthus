# Using MSR_LSTAR to hook system calls in Linux (Intel 64-bit only)

The [code](https://vvdveen.com/data/lstar.txt) is replicated by the post provided by Victor van der Veen.

This Linux kernel module hooks the MSR SYSENTER/SYSCALL. As stated in the Concept:

> [...] Whenever the syscall instruction is executed, the processor stores RIP in RCX and jumps to the address stored in the
LSTAR Model Specific Register (MSR). By changing the value of the LSTAR register, we can modify the kernel's system call entry point. [...] 

