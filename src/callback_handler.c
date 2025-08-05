#include "callback_handler.h"

// Example callback headers
#include "state_callbacks/module_list.h"
#include "event_callbacks/cr0_write.h"

state_task_callback_t get_state_task_callback(state_task_id_t id) {
    switch (id) {
        case STATE_KERNEL_MODULE_LIST:
            return state_module_list_callback;
        default:
            return NULL;
    }
}

event_task_callback_t get_event_task_callback(event_task_id_t id) {
    switch (id) {
        case EVENT_CR0_WRITE:
            return event_cr0_write_callback;
        default:
            return NULL;
    }
}
