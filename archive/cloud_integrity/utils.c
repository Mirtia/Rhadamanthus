#include "utils.h"

int post_clean_up(vmi_instance_t vmi, int ret_code) {
  // Resume the vm.
  if (vmi_resume_vm(vmi) == VMI_FAILURE) {
    fprintf(stderr, "Error at resuming the vmi instance.");
    return 1;
  };

  // Cleanup any memory associated with the libvmi instance.
  if (vmi_destroy(vmi) == VMI_FAILURE) {
    fprintf(stderr, "Error destroying vmi instance.");
    return 1;
  };

  // Return code is failure
  return ret_code;
}