#include "vmi.h"
#include <libvmi/libvmi.h>

int introspect_idt_check(const char *domain_name) {
  vmi_instance_t vmi;
  addr_t idt_addr, int_addr, kernel_start, kernel_end;
  int count_int = 0;

  uint64_t interrupt_number = 0;
  char **interrupt_index_table = NULL;

  char line[256];
  char name[256];
  int index[256];

  FILE *file;
  file = fopen("data/interrupt_index.linux", "r");
  if (!file) {
    fprintf(stderr, "Failed to open file.");
    return 1;
  }
  while (fgets(line, sizeof(line), file) != NULL) {
    sscanf(line, "%d\t%s", index, name);
    interrupt_index_table =
        realloc(interrupt_index_table, sizeof(char *) * ++interrupt_number);
    interrupt_index_table[interrupt_number - 1] = (char *)malloc(256);
    strcpy(interrupt_index_table[interrupt_number - 1], name);
  }
  fclose(file);

  vmi_init_data_t *init_data = NULL;
  /* initialize the libvmi library */
  if (VMI_FAILURE == vmi_init_complete(&vmi, domain_name, VMI_INIT_DOMAINNAME,
                                       init_data, VMI_CONFIG_GLOBAL_FILE_ENTRY,
                                       NULL, NULL)) {
    printf("Failed to init LibVMI library.\n");
    return 1;
  }

  vmi_get_vcpureg(vmi, &idt_addr, IDTR_BASE, 0);

  addr_t ntoskrnl, kernel_size;

  vmi_translate_ksym2v(vmi, "_stext", &kernel_start);
  vmi_translate_ksym2v(vmi, "_etext", &kernel_end);

  int i = 0;
  uint16_t addr1, addr2;
  uint32_t addr3;
  for (i = 0; i < interrupt_number; i++) {
    vmi_read_16_va(vmi, idt_addr + i * 16, 0, &addr1);
    vmi_read_16_va(vmi, idt_addr + i * 16 + 6, 0, &addr2);
    vmi_read_32_va(vmi, idt_addr + i * 16 + 8, 0, &addr3);
    int_addr = ((addr_t)addr3 << 32) + ((addr_t)addr2 << 16) + ((addr_t)addr1);

    if ((int_addr < kernel_start || int_addr > kernel_end) &&
        (strcmp(interrupt_index_table[i], "unknown"))) {
      printf("interrupt handler %s address changed to 0x%" PRIx64 "\n",
             interrupt_index_table[i], int_addr);
      count_int++;
    }
  }

  printf("%d interrupt handlers have been hooked\n", count_int);

exit:
  vmi_destroy(vmi);
  return 0;
}
