#include "dispatcher.h"
#include <log.h>

dispatcher_t *dispatcher_initialize(vmi_instance_t vmi)  {
    dispatcher_t *dispatcher = g_malloc0(sizeof(dispatcher_t));
    if (!dispatcher) return NULL;
    
    dispatcher->vmi = vmi;
    g_mutex_init(&dispatcher->vm_mutex);

    return dispatcher;
}
