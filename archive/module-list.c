/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <libvmi/libvmi.h>

int main(int argc, char **argv) {
  vmi_instance_t vmi = {0};
  addr_t next_module = 0;
  addr_t list_head = 0;
  int retcode = 1;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <domain_name>", argv[0]);
    return retcode;
  }

  // This is the VM or file that we are looking at.
  char *name = argv[1];

  // Initialize the libvmi library.
  if (VMI_FAILURE == vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME, NULL,
                                       VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL,
                                       NULL)) {
    printf("Failed to init LibVMI library.\n");
    goto error_exit;
  }

  // Pause the vm for consistent memory access.
  if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
    printf("Failed to pause VM.\n");
    goto error_exit;
  }

  os_t os = vmi_get_ostype(vmi);
  if (VMI_OS_LINUX != os) {
    fprintf(stderr, "Unsupported OS. Only Linux supported.\n");
    goto error_exit;
  }

  if (vmi_read_addr_ksym(vmi, "modules", &next_module) == VMI_FAILURE) {
    fprintf(stderr, "Failed to read kernel symbol `modules`.\n");
    goto error_exit;
  }

  list_head = next_module;

  // Walk the module list.
  while (1) {

    // Follow the next pointer.
    addr_t tmp_next = 0;

    vmi_read_addr_va(vmi, next_module, 0, &tmp_next);

    // If we are back at the list head, we are done.
    if (list_head == tmp_next) {
      break;
    }

    /* Note: the module struct that we are looking at has a string
     * directly following the next / prev pointers.  This is why you
     * can just add the length of 2 address fields to get the name.
     * See include/linux/module.h for mode details
     */
    char *modname = NULL;
    // 64-bit paging
    if (VMI_PM_IA32E == vmi_get_page_mode(vmi, 0)) {
      modname = vmi_read_str_va(vmi, next_module + 16, 0);
    } else {
      modname = vmi_read_str_va(vmi, next_module + 8, 0);
    }
    printf("%s\n", modname);
    free(modname);
    next_module = tmp_next;
  }

  retcode = 0;
error_exit:
  // Resume the vm.
  vmi_resume_vm(vmi);

  // Cleanup any memory associated with the libvmi instance.
  vmi_destroy(vmi);

  return retcode;
}
