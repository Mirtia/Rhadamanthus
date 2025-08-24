#ifndef EBPF_ARTIFACTS_H
#define EBPF_ARTIFACTS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief 
 * 
 * @param vmi 
 * @param context 
 * @return uint32_t 
 */
uint32_t state_ebpf_artifacts_callback(vmi_instance_t vmi, void* context);

#endif // EBPF_ARTIFACTS_H
