/**
 * @file ftrace_hooks.h
 * @author Myrsini Gkolemi  
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
 * @param vmi The VMI instance.
 * @param context The user-defined context [unused].
 * @return uint32_t VMI_SUCCESS on successful inspection else VMI_FAILURE.
 */
uint32_t state_ftrace_hooks_callback(vmi_instance_t vmi, void* context);

#endif  // FTRACE_HOOKS_H