#ifndef KPROBES_JPROBES_KRETPROBES_H
#define KPROBES_JPROBES_KRETPROBES_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_kprobes_jprobes_kretprobes_callback(vmi_instance_t vmi, void* context);

#endif // KPROBES_JPROBES_KRETPROBES_H
