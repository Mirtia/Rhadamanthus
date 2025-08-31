#include "vmi.h"

int introspect_process_list(const char* domain_name) {
  vmi_instance_t vmi = {0};
  addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
  addr_t current_process = 0;
  char* procname = NULL;
  vmi_pid_t pid = 0;
  unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;
  status_t status = VMI_FAILURE;
  vmi_init_data_t* init_data = NULL;
  uint64_t domid = 0;
  uint8_t init = VMI_INIT_DOMAINNAME,
          config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
  void *input = NULL, *config = NULL;
  int retcode = 1;

  init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));

  if (VMI_FAILURE == vmi_init_complete(&vmi, (void*)domain_name,
                                       VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS,
                                       init_data, VMI_CONFIG_GLOBAL_FILE_ENTRY,
                                       NULL, NULL)) {
    printf("Failed to init LibVMI library.\n");
    goto exit;
  }

  vmi_pause_vm(vmi);

  /**
   * get offsets of the kernel data structures
   * get the head of the task_struct
   */

  switch (vmi_get_ostype(vmi)) {
    case VMI_OS_LINUX:
      vmi_get_offset(vmi, "linux_tasks", &tasks_offset);
      vmi_get_offset(vmi, "linux_name", &name_offset);
      vmi_get_offset(vmi, "linux_pid", &pid_offset);

      vmi_translate_ksym2v(vmi, "init_task", &list_head);
      list_head += tasks_offset;

      break;
    case VMI_OS_WINDOWS:
      vmi_get_offset(vmi, "win_tasks", &tasks_offset);
      vmi_get_offset(vmi, "win_pname", &name_offset);
      vmi_get_offset(vmi, "win_pid", &pid_offset);

      vmi_translate_ksym2v(vmi, "PsActiveProcessHead", &list_head);

      break;
    default:
      goto exit;
  }

  if (tasks_offset == 0 || pid_offset == 0 || name_offset == 0) {
    printf("Failed to find offsets\n");
    goto exit;
  }

  next_list_entry = list_head;

  /**
   * traverse the task lists and print out each process
   */
  do {
    current_process = next_list_entry - tasks_offset;
    vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);
    procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
    if (!procname) {
      printf("Failed to find procname\n");
      goto exit;
    }

    printf("[%5d] %s\n", pid, procname);

    free(procname);
    procname = NULL;

    if (vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry) ==
        VMI_FAILURE) {
      printf("Failed to read next pointer in loop at %" PRIx64 "\n",
             next_list_entry);
      goto exit;
    }

  } while (next_list_entry != list_head);

exit:
  vmi_resume_vm(vmi);
  vmi_destroy(vmi);

  return 0;
}
