/**
 * @file ftrace_hooks.h
 * @brief This file contains the callback function to detect ftrace hooks.
 * @version 0.0
 * @date 2025-08-24
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef FTRACE_HOOKS_H
#define FTRACE_HOOKS_H
#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief Callback function to detect ftrace hooks. The detection method tries to unfold/follow the technique
 * observed in https://github.com/ilammy/ftrace-hook/blob/master/ftrace_hook.c.
 * 
 * The detection method tries (some failed some not):
 * 1. **Direct Memory Scanning** (OK) - Scans known rootkit target functions for CALL/JMP instructions
 *    pointing to module space. This is the primary working method.
 * 2. **Ftrace Operations Analysis** (OK) - Walks ftrace_ops_list to find callbacks outside kernel text.
 *    Detects hooks by analyzing ftrace operation structures.
 * 3. **Ftrace Pages Enumeration** (FAILED) - Attempted to walk ftrace_pages linked list to enumerate
 *    dyn_ftrace records. Failed due to skill issue.
 * 4. **__mcount_loc Table Parsing** (FAILED) - Attempted to parse build-time __mcount_loc section.
 *    The resolution of the calls sites did not work likely due to skill issue.
 * 5. **Dynamic Module Region Discovery** (FAILED) - Attempted to dynamically discover module memory
 *    regions using known symbols. Caused massive false positives due to overly broad 256MB estimation.
 * @param vmi The VMI instance.
 * @param context The user-defined context [unused].
 * @return uint32_t VMI_SUCCESS on successful inspection else VMI_FAILURE.
 */
uint32_t state_ftrace_hooks_callback(vmi_instance_t vmi, void* context);

#endif  // FTRACE_HOOKS_H