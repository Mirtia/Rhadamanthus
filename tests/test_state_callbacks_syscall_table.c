#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <log.h>
#include <libvmi/libvmi.h>

#include "state_callbacks/syscall_table.h"

static void test_syscall_table_callback(void** state) {
  (void)state;

  const char* domain_name = "ubuntu-20-04-dbg";
  vmi_instance_t vmi = {0};

  if (VMI_FAILURE == vmi_init_complete(&vmi, domain_name, VMI_INIT_DOMAINNAME,
                                       NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL,
                                       NULL)) {
    fail_msg("Failed to initialize LibVMI for test domain: %s", domain_name);
  }

  uint32_t result = state_syscall_table_callback(vmi, NULL);
  assert_int_equal(result, VMI_SUCCESS);
  vmi_destroy(vmi);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_syscall_table_callback),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
