#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

uint32_t state_credentials_callback(vmi_instance_t vmi, void* context);

#endif // CREDENTIALS_H
