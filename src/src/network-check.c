#include "vmi.h"

int introspect_network_check(char *name) {
  vmi_instance_t vmi = {0};
  vmi_init_data_t *init_data = NULL;
  /* initialize the libvmi library */
  if (VMI_FAILURE == vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME,
                                       init_data, VMI_CONFIG_GLOBAL_FILE_ENTRY,
                                       NULL, NULL)) {
    printf("Failed to init LibVMI library.\n");
    return 1;
  }

  addr_t tcp_hashinfo_addr;
  addr_t node_addr;
  addr_t udp_table_addr;

  uint16_t sport;

  unsigned long hlistOffset = 0x40;
  unsigned long hlistLength = 0x10;
  unsigned long firstOffset = 0x8;
  unsigned long sportOffset = 0x28c;
  unsigned long nextOffset = 0x0;

  unsigned long uhlistOffset = 0x0;
  unsigned long uhlistLength = 0x10;
  unsigned long ufirstOffset = 0x0;
  // What are those symbols?? Dafuq
  vmi_translate_ksym2v(vmi, "tcp_hashinfo", &tcp_hashinfo_addr);
  vmi_translate_ksym2v(vmi, "udp_table", &udp_table_addr);

  int i;
  printf("TCP ports: \n");
  for (i = 0; i < 32; i++) {
    vmi_read_addr_va(
        vmi, tcp_hashinfo_addr + hlistOffset + i * hlistLength + firstOffset, 0,
        &node_addr);
    // Non terminating condition
    while (!((unsigned long)node_addr & 1)) {
      vmi_read_16_va(vmi, node_addr + sportOffset, 0, &sport);
      uint16_t port = ((sport & 0xFF) << 8) + (sport >> 8);
      printf("%" PRIu16 "\n", port);
      vmi_read_addr_va(vmi, node_addr + nextOffset, 0, &node_addr);
    }
  }

  // printf("UDP ports: \n");
  // addr_t hash_addr;
  // for (i = 0; i < 1024; i++) {
  //   vmi_read_addr_va(vmi, udp_table_addr + uhlistOffset, 0, &hash_addr);
  //   vmi_read_addr_va(vmi, hash_addr + i * uhlistLength + ufirstOffset, 0,
  //                    &node_addr);

  //   while (!((unsigned long)node_addr & 1)) {
  //     vmi_read_16_va(vmi, node_addr + sportOffset, 0, &sport);
  //     uint16_t port = ((sport & 0xFF) << 8) + (sport >> 8);
  //     printf("%" PRIu16 "\n", port);
  //     vmi_read_addr_va(vmi, node_addr + nextOffset, 0, &node_addr);
  //   }
  // }

exit:
  vmi_destroy(vmi);

  return 0;
}
