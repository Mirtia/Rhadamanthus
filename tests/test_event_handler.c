#include <log.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include "event_handler.h"

void register_mock_tasks(event_handler_t* event_handler) {
  // This function registers some events and tasks.
  if (!event_handler) {
    log_error("The provided event_handler is NULL.");
    return;
  }
  log_info("Mock tasks registered.");
}

static void test_event_handler_creation_invalid(void** state) {
  (void)state;
  event_handler_t* event_handler_invalid =
      event_handler_initialize(NULL, 1000, 100);
  // Since the vmi instance passed is null, so is the return value of the `event_handler_initialize` function.
  assert_null(event_handler_invalid);
  event_handler_free(event_handler_invalid);
}

static void test_event_handler_creation_valid(void** state) {
  (void)state;
  // Create a valid vmi instance, domain_name should already be defined in the test setup.
  // TODO: Have a setup script for setting up XEN vms and snapshots.
  vmi_instance_t vmi = {0};
  const char* domain_name = "ubuntu-20-04-dbg";
  if (VMI_FAILURE == vmi_init_complete(&vmi, domain_name, VMI_INIT_DOMAINNAME,
                                       NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL,
                                       NULL)) {
    log_error("Failed to init LibVMI library.\n");
    vmi_destroy(vmi);
  }
  uint32_t window_seconds = 1;
  uint32_t state_sampling_seconds = 1;
  event_handler_t* event_handler_valid =
      event_handler_initialize(vmi, window_seconds, state_sampling_seconds);
  assert_non_null(event_handler_valid);
  assert_int_equal(event_handler_valid->window_seconds, window_seconds);
  assert_int_equal(event_handler_valid->state_sampling_seconds, state_sampling_seconds);
  assert_int_equal(event_handler_valid->vmi, vmi);

  assert_non_null(event_handler_valid->state_tasks);
  for (int i = 0; i < STATE_TASK_ID_MAX; i++) {
    assert_null(event_handler_valid->state_tasks[i]);
  }
  assert_non_null(event_handler_valid->event_tasks);
  for (int i = 0; i < EVENT_TASK_ID_MAX; i++) {
    assert_null(event_handler_valid->event_tasks[i]);
  }

  assert_null(event_handler_valid->event_thread);
  event_handler_free(event_handler_valid);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_event_handler_creation_valid),
      cmocka_unit_test(test_event_handler_creation_invalid)};

  return cmocka_run_group_tests(tests, NULL, NULL);
}
