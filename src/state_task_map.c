#include "state_task_map.h"

#include "state_callbacks/kernel_module_list.h"
#include "state_callbacks/process_list.h"
#include "state_callbacks/syscall_table.h"
// TODO: Add more includes for other state callbacks.

uint32_t (*get_state_task_functor(state_task_id_t task_id))(vmi_instance_t,
                                                            void*) {
  switch (task_id) {
    case STATE_SYSCALL_TABLE:
      return state_syscall_table_callback;
    case STATE_PROCESS_LIST:
      return state_process_list_callback;
    case STATE_KERNEL_MODULE_LIST:
      return state_kernel_module_list_callback;
    // TODO: Add the rest of the mappings.
    default:
      return NULL;
  }
}