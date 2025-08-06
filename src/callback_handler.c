#include "callback_handler.h"
#include "event_callbacks/cr0_write.h"
#include "state_callbacks/kernel_module_list.h"

state_task_callback_t get_state_task_callback(state_task_id_t task_id) {
  switch (task_id) {
    case STATE_KERNEL_MODULE_LIST:
      return state_kernel_module_list_callback;
    default:
      return NULL;
  }
}

event_task_callback_t get_event_task_callback(event_task_id_t task_id) {
  switch (task_id) {
    case EVENT_CR0_WRITE:
      return event_cr0_write_callback;
    default:
      return NULL;
  }
}
