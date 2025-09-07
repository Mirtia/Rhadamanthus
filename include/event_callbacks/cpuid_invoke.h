/**
 * @file cpuid_invoke.h
 * @author Myrsini Gkolemi
 * @brief 
 * @version 0.0
 * @date 2025-09-07
 * 
 * @copyright Copyright (c) 2025
 * 
 * @copyright GNU Lesser General Public License v2.1
 * @remark The implementation follows the example cpuid provided by LibVMI 
 * (https://github.com/libvmi/libvmi/blob/master/examples/cpuid.c)
 */
#ifndef CPUID_INVOKE_H
#define CPUID_INVOKE_H

// TODO: Not urgent. But it is interesting since an attacker may use cpuid instruction to understand 
// the environment (e.g., if it is running in a VM or not) and the architecture (e.g., x86_64).
// On Xen, executing cpuid will show a legitimate vendor ID (e.g., GenuineIntel) and not Xen.

#endif // CPUID_INVOKE_H