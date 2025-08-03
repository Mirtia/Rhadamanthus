#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libvmi/events.h>
#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <openssl/md5.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <unistd.h>

/**
 * default is using INT 3 for event notification
 * if MEM_EVENT is defined, then using EPT violation
 */

#define MEM_EVENT

/* task_struct offsets */
extern unsigned long tasks_offset;
extern unsigned long pid_offset;
extern unsigned long name_offset;

static int set_breakpoint(vmi_instance_t vmi, addr_t addr, pid_t pid) {

  uint32_t data;
  if (VMI_FAILURE == vmi_read_32_va(vmi, addr, pid, &data)) {
    printf("failed to read memory.\n");
    return -1;
  }
  data = (data & 0xFFFFFF00) | 0xCC;
  if (VMI_FAILURE == vmi_write_32_va(vmi, addr, pid, &data)) {
    printf("failed to write memory.\n");
    return -1;
  }
  return 0;
}

static int interrupted = 0;

static void close_handler(int sig) { interrupted = sig; }

// TODO(mirtia): Add docstrings for each one of those.
int introspect_process_list(const char *domain_name);

int introspect_module_list(const char *domain_name);

int introspect_syscall_check(const char *domain_name);

int introspect_kernel_check(const char *domain_name);

int introspect_idt_check(const char *domain_name);

int introspect_network_check(const char *domain_name);

int introspect_procfs_check(const char *domain_name);

int introspect_syscall_trace(const char *domain_name);

int introspect_socketapi_trace(const char *domain_name);

int introspect_driverapi_trace(const char *domain_name);

int introspect_sleepapi_nop(const char *domain_name);

int introspect_process_block(const char *domain_name);

int introspect_process_kill(const char *domain_name, const char *arg);
