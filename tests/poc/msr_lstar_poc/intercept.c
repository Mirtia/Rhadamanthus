#include <linux/delay.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/percpu.h>
#include <asm/msr.h>
#include <asm/processor.h>

#include "constants.h"

MODULE_AUTHOR("Victor van der Veen");
MODULE_DESCRIPTION("Intercept syscalls via MSR_LSTAR");
MODULE_LICENSE("GPL");

/* Declare per-CPU variable to hold saved user RSP */
DEFINE_PER_CPU(unsigned long, saved_user_rsp);


void (*syscall_orig)(void) = NULL;
void (*syscall_after_swapgs)(void);
extern void syscall_new(void);

void do_c_sigreturn(void) {
    printk("SIGRETURN!\n");
}

/* Write to MSR_LSTAR on all CPUs */
void update_lstar(void* addr) {
    wrmsrl(MSR_LSTAR, (unsigned long)addr);
}

static void print_gs_offsets(void) {
    unsigned long gs_base;
    unsigned long rsp_offset, stack_offset;

    rdmsrl(MSR_GS_BASE, gs_base);
    rsp_offset   = (unsigned long)per_cpu(saved_user_rsp, smp_processor_id()) - gs_base;
    stack_offset = (unsigned long)per_cpu(cpu_current_top_of_stack, smp_processor_id()) - gs_base;

    printk(KERN_INFO "Update constants.S with the following offsets:\n");
    printk(KERN_INFO "#define OLD_RSP      0x%lx\n", rsp_offset);
    printk(KERN_INFO "#define KERNEL_STACK 0x%lx\n", stack_offset);
}


int intercept_syscalls_init(void) {
    uint64_t value;

    print_gs_offsets();  // ← key addition

    rdmsrl(MSR_LSTAR, value);
    syscall_orig = (void (*)(void))value;

    on_each_cpu(update_lstar, syscall_new, 1);
    return 0;
}

void intercept_syscalls_exit(void) {
    if (syscall_orig == NULL)
        return;

    on_each_cpu(update_lstar, syscall_orig, 1);
    msleep(1000);
    syscall_orig = NULL;
}

static int __init intercept_init(void) {
    if (intercept_syscalls_init() < 0) {
        printk("Failed to intercept system calls\n");
        return -1;
    }
    return 0;
}

static void __exit intercept_exit(void) {
    intercept_syscalls_exit();
}

module_init(intercept_init);
module_exit(intercept_exit);
