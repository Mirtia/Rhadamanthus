# Scenarios

## Overview

This document outlines the rootkit scenarios used to test and validate the Rhadamanthus VMI Linux Rootkit Detection Framework. Each scenario represents different attack vectors and rootkit techniques commonly observed in the wild. The subsection *Attack Indicators* is focusing more on kernel-related indicators but user-space indicators are also mentioned partially.

## [bad-bpf](https://github.com/pathtofile/bad-bpf)

This repository contains examples of malicious eBPF usage demonstrating how eBPF programs can be abused for rootkit functionality. See the original analysis [here](https://blog.tofile.dev/2021/08/01/bad-bpf.html).

### Attack Techniques

As stated (slightly paraphrased) in the article, bad-bpf demonstrates:
- **Privilege escalation**: Intercepting sudo read calls to enable low-privileged users to elevate to root
- **Process hijacking**: Hijacking execve calls to change the program being launched
- **Process hiding**: Hiding processes from ps by intercepting directory listings to /proc
- **Data manipulation**: Replacing arbitrary text in files (kernel module hiding, MAC address faking)
- **System call blocking**: Denying other eBPF syscall usage by sending SIGKILL
- **Return value spoofing**: Faking sys_write return values to deceive applications

### Detection Coverage



### Demo

Insert video here or pictures

## [curing (io-uring PoC)](https://github.com/armosec/curing)

Curing demonstrates a non-traditional rootkit approach using the io_uring interface, which was recently [exploited](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/) for rootkit functionality.

### Attack Techniques

### Detection Coverage

### Outside Coverage

### Demo

Insert video here or pictures

## [ftrace-hooked based LKM](https://github.com/bluedragonsecurity/bds_lkm_ftrace)

Ftrace hooking has become one of the most common methods for implementing kernel-level rootkits, providing a stealthy way to intercept and modify kernel function calls. We do not enable persistence for the `bds_lkm_ftrace` as persistence is out of the scope.

### Attack Techniques

- **Ftrace Hooks Registration**: 

```c
// bds_ftrace_hooks.c
static struct ftrace_hook hooks[] = {
	HOOK("tcp4_seq_show", bds_tcp4_seq_show, &orig_tcp4_seq_show),
	HOOK("tcp6_seq_show", bds_tcp6_seq_show, &orig_tcp6_seq_show),
	HOOK("__x64_sys_getdents64", bds_getdents64, &orig_getdents64),
	HOOK("__x64_sys_getdents", bds_getdents, &orig_getdents),
	HOOK("__x64_sys_kill", bds_kill, &orig_kill),
};
```

- **Kprobe registration**:

TODO

- **Hidden processes**: Expected discrepancy with in-guest monitoring. 
- **Hidden connections**: Expected discrepancy with in-guest monitoring. 
- **Hidden module**: Expected discrepancy with in-guest monitoring.

## Outside coverage

- **Credential manipulation**: Process credentials are visible through [`state_callbacks/process_list.c`](src/state_callbacks/process_list.c) but not directly detected

### Demo

Insert video here or pictures

## [Diamorphine](https://github.com/m0nad/Diamorphine)

Diamorphine is a classic Linux kernel rootkit compatible with kernels 5.x/6.x and x86_64 architecture. It demonstrates typical rootkit stealth behaviors and has been observed in recent attacks with variants in the [wild](https://www.broadcom.com/support/security-center/protection-bulletin/new-strain-of-diamorphine-linux-rootkit).

### Attack Techniques

Diamorphine implements traditional rootkit techniques including:
- **System call table modification**: Direct patching of kernel syscall handlers
- **Process hiding**: Making malicious processes invisible to userspace tools
- **Module hiding**: Removing the rootkit module from kernel module lists
- **Privilege escalation**: Granting root privileges to specific processes
- **Custom signal handling**: Using non-standard signals for rootkit communication

### Detection Coverage

Diamorphine triggers the following detection indicators:

- **CR0 Write Protection Disable**:

```c
// diamorphine.c:340
static inline void
write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;
	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}
#endif
```

- **System Call Table Modification**:

```c
// diamorphine.c:413
__sys_call_table[__NR_getdents] = (unsigned long) hacked_getdents;
__sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;
__sys_call_table[__NR_kill] = (unsigned long) hacked_kill;
```

- **Module Hiding**: Expected discrepancy with in-guest monitoring. 

```c
// diamorphine.c:293
void
module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}
```

- **Process Hiding**: Expected discrepancy with in-guest monitoring. 

```c
// diamorphine.h:10
#define PF_INVISIBLE 0x10000000
```

- **Kprobe registration**:

TODO

### Outside Coverage

- **Credential manipulation**: Process credentials are visible through [`state_callbacks/process_list.c`](src/state_callbacks/process_list.c) but not directly detected
- **Custom signal handling**: Diamorphine-specific signals like `SIGSUPER` for privilege escalation are not tracked
```c
// diamorphine.h:14
enum {
	SIGINVIS = 31,
	SIGSUPER = 64,
	SIGMODINVIS = 63,
};
```

### Demo

Insert video here or pictures

## Results

Show indicator percentage.
