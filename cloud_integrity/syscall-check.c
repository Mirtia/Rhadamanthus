#include "vmi.h"

int introspect_syscall_check(const char *domain_name) {
  vmi_instance_t vmi = {0};
  addr_t sys_call_table_addr, sys_call_addr, kernel_start, kernel_end = 0;
  int syscall_hit_count = 0;

  char **sys_index = NULL;
  size_t syscall_number = 0;
  int retcode = 1;

  char _line[256];
  char _name[256];
  int _index[256];

  FILE *_file;
  // TODO(mirtia): Check that the syscall index is correct.
  _file = fopen("data/syscall_index.linux", "r");
  if (!_file) {
    printf("Failed to open file.\n");
    goto error_exit;
  }

  // Parse the syscall file.
  while (fgets(_line, sizeof(_line), _file) != NULL) {
    sscanf(_line, "%d\t%s", _index, _name);
    sys_index = realloc(sys_index, sizeof(char *) * ++syscall_number);
    sys_index[syscall_number - 1] = (char *)malloc(256);
    strcpy(sys_index[syscall_number - 1], _name);
  }
  fclose(_file);

  if (VMI_FAILURE == vmi_init_complete(&vmi, domain_name, VMI_INIT_DOMAINNAME, NULL,
                                       VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL,
                                       NULL)) {
    printf("Failed to init LibVMI library.\n");
    return 1;
  }

  // Get the OS of the vm.
  os_t os = vmi_get_ostype(vmi);
  if (VMI_OS_LINUX != os) {
    fprintf(stderr, "Unsupported OS. Only Linux supported.\n");
    goto error_exit;
  }

  // Get syscall table address.
  vmi_translate_ksym2v(vmi, "sys_call_table", &sys_call_table_addr);

  // Get kernel function boundary.
  vmi_translate_ksym2v(vmi, "_stext", &kernel_start);
  vmi_translate_ksym2v(vmi, "_etext", &kernel_end);

  int start_index = 0;

  for (size_t i = start_index; i < syscall_number; ++i) {
    vmi_read_addr_va(vmi, sys_call_table_addr + i * 8, 0, &sys_call_addr);
    // If the system call address lies outside the kernel's .text section,
    // it may indicate that the syscall handler has been modified or redirected,
    // potentially due to hooking or tampering.
    if (sys_call_addr < kernel_start || sys_call_addr > kernel_end) {
      printf("sys_call %s address changed to 0x%" PRIx64 "\n", sys_index[i],
             sys_call_addr);
      syscall_hit_count++;
    }
  }

  printf("%d syscalls have been hooked\n", syscall_hit_count);

error_exit:
  // Resume the vm.
  vmi_resume_vm(vmi);

  // Cleanup any memory associated with the libvmi instance.
  vmi_destroy(vmi);

  return retcode;
}