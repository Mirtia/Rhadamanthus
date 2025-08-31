#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MODULE_LIST_OFF 0x08
#define MODULE_NAME_OFF 0x18
#define MODULE_NAME_LEN 56
#define MODULE_CORELAYOUT_OFF 0x140
#define MODL_BASE_OFF 0x00
#define MODL_SIZE_OFF 0x08

static int post_clean_up(vmi_instance_t vmi, int retcode) {
  vmi_resume_vm(vmi);
  vmi_destroy(vmi);
  return retcode;
}

int introspect_module_list(const char* domain_name) {
  vmi_instance_t vmi = {0};
  addr_t list_head = 0;
  addr_t cur_link = 0;

  if (vmi_init_complete(&vmi, domain_name, VMI_INIT_DOMAINNAME, NULL,
                        VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL,
                        NULL) == VMI_FAILURE) {
    fprintf(stderr, "Failed to init LibVMI.\n");
    return 1;
  }

  if (vmi_pause_vm(vmi) == VMI_FAILURE) {
    fprintf(stderr, "Failed to pause VM.\n");
    return post_clean_up(vmi, 1);
  }

  if (vmi_get_ostype(vmi) != VMI_OS_LINUX) {
    fprintf(stderr, "Unsupported OS. Only Linux supported.\n");
    return post_clean_up(vmi, 1);
  }

  // addr_t list_head = 0xffffffff8b9ce640;

  if (vmi_translate_ksym2v(vmi, "modules", &list_head) == VMI_FAILURE) {
    fprintf(stderr, "Failed to resolve address of 'modules'.\n");
    return post_clean_up(vmi, 1);
  }

  printf("[+] modules list_head address: 0x%016" PRIx64 "\n", list_head);

  cur_link = list_head;
  size_t mod_index = 0;
  size_t max_modules = 512;

  while (mod_index++ < max_modules) {
    addr_t next_link = 0;

    if (vmi_read_addr_va(vmi, cur_link, 0, &next_link) == VMI_FAILURE) {
      fprintf(stderr, "Failed to read next pointer at 0x%" PRIx64 ".\n",
              cur_link);
      break;
    }

    if (next_link == list_head)
      break;

    addr_t mod_base = next_link - MODULE_LIST_OFF;
    addr_t name_addr = mod_base + MODULE_NAME_OFF;
    addr_t layout_addr = mod_base + MODULE_CORELAYOUT_OFF;

    char namebuf[MODULE_NAME_LEN + 1] = {0};
    size_t nread = 0;
    if (vmi_read_va(vmi, name_addr, 0, MODULE_NAME_LEN, namebuf, &nread) ==
            VMI_FAILURE ||
        nread == 0) {
      strncpy(namebuf, "<unreadable>", MODULE_NAME_LEN);
    } else {
      namebuf[MODULE_NAME_LEN] = '\0';
    }

    addr_t base = 0;
    uint32_t size = 0;

    if (vmi_read_addr_va(vmi, layout_addr + MODL_BASE_OFF, 0, &base) ==
        VMI_FAILURE) {
      fprintf(stderr,
              "Warning: could not read base of module @ 0x%" PRIx64 "\n",
              layout_addr);
    }

    if (vmi_read_32_va(vmi, layout_addr + MODL_SIZE_OFF, 0, &size) ==
        VMI_FAILURE) {
      fprintf(stderr,
              "Warning: could not read size of module @ 0x%" PRIx64 "\n",
              layout_addr);
    }

    printf("Module %3zu: %-20s  Base: 0x%016" PRIx64 "  Size: %u (0x%x)\n",
           mod_index, namebuf[0] ? namebuf : "<noname>", base, size, size);

    cur_link = next_link;
  }

  return post_clean_up(vmi, 0);
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <vm_name>\n", argv[0]);
    return 1;
  }
  return introspect_module_list(argv[1]);
}
