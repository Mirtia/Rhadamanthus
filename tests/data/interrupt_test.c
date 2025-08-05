#include <unistd.h>

/**
 * @brief Cause a breakpoint interrupt (int3) to trigger related events in the introspector.
 */
void trigger_point() {
  asm volatile("int3");
}

int main() {
  // Sleep so that there is time for the Introspector to get the process id.
  sleep(3);
  trigger_point();
  return 0;
}