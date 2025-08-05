#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <log.h>
#include "dispatcher.h"

void register_mock_tasks(dispatcher_t* dispatcher) {
  // This function registers some events and tasks.
  log_info("Mock tasks registered.");

}

static void test_dispatcher_creation(void** state) {
  (void)state;

  dispatcher_t* dispatcher_invalid = dispatcher_initialize(NULL, 1000, 100);
  // Since the vmi instance passed is null, so is the return value of the `dispatcher_initialize` function.
  assert_null(dispatcher_invalid);

  // Create a valid vmi instance, domain_name should already be defined in the test setup.
  // TODO: Have a setup script for setting up XEN vms and snapshots.
  vmi_instance_t vmi = {0};
  const char* domain_name = "ubuntu-20-04";
  if (VMI_FAILURE == vmi_init_complete(&vmi, domain_name, VMI_INIT_DOMAINNAME,
                                       NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL,
                                       NULL)) {
    log_error("Failed to init LibVMI library.\n");
    vmi_destroy(vmi);
  }
  uint32_t window_ms = 1000;
  uint32_t state_sampling_ms = 100;
  dispatcher_t* dispatcher_valid =
      dispatcher_initialize(vmi, window_ms, state_sampling_ms);
  assert_non_null(dispatcher_valid);
  assert_int_equal(dispatcher_valid->window_ms, window_ms);
  assert_int_equal(dispatcher_valid->state_sampling_ms, state_sampling_ms);
  assert_int_equal(dispatcher_valid->vmi, vmi);

  assert_non_null(dispatcher_valid->state_tasks);
  for (int i = 0; i < STATE_TASK_ID_MAX; i++) {
    assert_null(dispatcher_valid->state_tasks[i]);
  }
  assert_non_null(dispatcher_valid->event_tasks);
  for (int i = 0; i < EVENT_TASK_ID_MAX; i++) {
    assert_null(dispatcher_valid->event_tasks[i]);
  }

  assert_null(dispatcher_valid->event_thread);
  assert_null(dispatcher_valid->state_thread);
  assert_null(dispatcher_valid->event_worker_thread);
  assert_int_equal(g_async_queue_length(dispatcher_valid->event_queue), 0);

  // Now, I would like to create some function that registers some events.
  register_mock_tasks(dispatcher_valid);

}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_dispatcher_creation),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
