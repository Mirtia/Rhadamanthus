#include "test_utils.h"
#include <log.h>
#include "dispatcher.h"

void register_mock_tasks(dispatcher_t* dispatcher) {
  // This function registers some events and tasks.
  log_info("Mock tasks registered.");
  // The state task can be simply mocked as it does not require a trigger mechanism like events.
}

void setup_interrupt_test(vmi_instance_t vmi, const char* file_path) {
  // Drakvuf can be used to transfer files and inject (start) processes.
  // The interrupt_test.c file has to be passed to the vmi instance. The path can be provided in relation to the repository as a precompiler flag with CMake.
  // Then it should be compiled with --no-pie and -g so that the address of the trigger_function is fixed and known.
  // The executable should be run and then the vm paused to identify the process id.
  // We also have to run nm to find the address of the trigger_point function.
  // Then a new vmi event should be created that triggers on the breakpoint interrupt (int3), since pid is known we can use it to calculate address.

  // Instead, since the config for the vm will be provided, and probably also a snapshot that already has the file compiled with the required options,
  // then the offest could be hard coded and drakvuf may just inject the process.
  log_info("Interrupt test setup completed.");
}

void mock_task_callback_event_task(vmi_instance_t vmi, vmi_event_t* event) {
  (void)vmi;
  (void)event;
  log_info("Mock event task callback executed.");
}

void mock_task_callback_state_task(vmi_instance_t vmi, vmi_event_t* event) {
  (void)vmi;
  (void)event;
  log_info("Mock state task callback executed.");
}