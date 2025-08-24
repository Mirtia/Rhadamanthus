#ifndef DIR_STRING_MATCHING_H
#define DIR_STRING_MATCHING_H

#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief Callback function to detect potentially hidden or known directories or files associated with observed kernel-mode rootkits.
 * 
 * @param vmi The VMI instance.
 * @param context The user-defined context [unused].
 * @return uint32_t VMI_SUCCESS on successful inspection else VMI_FAILURE.
 */
uint32_t state_dir_string_matching_callback(vmi_instance_t vmi, void* context);

#endif  // DIR_STRING_MATCHING_H
