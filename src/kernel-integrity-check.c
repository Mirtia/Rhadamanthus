#include "vmi.h"
#include <openssl/evp.h>
#include <stdio.h>

int introspect_kernel_check(char *name) {
  vmi_instance_t vmi;
  addr_t kernel_start, kernel_end;
  vmi_init_data_t *init_data = NULL;
  status_t status;

  if (VMI_FAILURE == vmi_init_complete(&vmi, name, VMI_INIT_DOMAINNAME,
                                       init_data, VMI_CONFIG_GLOBAL_FILE_ENTRY,
                                       NULL, NULL)) {
    printf("Failed to init LibVMI library.\n");
    return 1;
  }

  /**
   * Get kernel function boundary.
   */
  if (VMI_FAILURE == vmi_translate_ksym2v(vmi, "_stext", &kernel_start)) {
    printf("Failed to find _stext symbol\n");
    goto exit;
  }

  if (VMI_FAILURE == vmi_translate_ksym2v(vmi, "_etext", &kernel_end)) {
    printf("Failed to find _etext symbol\n");
    goto exit;
  }

  // Modern OpenSSL EVP interface
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  char buf[512];
  size_t bytes;

  // Initialize hash context
  md = EVP_sha256();
  mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    printf("Failed to create hash context\n");
    goto exit;
  }

  if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
    printf("Failed to initialize hash\n");
    EVP_MD_CTX_free(mdctx);
    goto exit;
  }

  addr_t i;
  for (i = kernel_start; i < kernel_end; i += 512) {
    status = vmi_read_va(vmi, i, 0, 512, buf, &bytes);
    if (status == VMI_FAILURE) {
      printf("Failed to read memory at address 0x%lx\n", i);
      continue; // Skip failed reads rather than abort
    }

    if (EVP_DigestUpdate(mdctx, buf, bytes) != 1) {
      printf("Failed to update hash\n");
      EVP_MD_CTX_free(mdctx);
      goto exit;
    }
  }

  if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
    printf("Failed to finalize hash\n");
    EVP_MD_CTX_free(mdctx);
    goto exit;
  }

  EVP_MD_CTX_free(mdctx);

  printf("Kernel section hash value (SHA256): ");
  unsigned int j;
  for (j = 0; j < hash_len; j++)
    printf("%02x", hash[j]);
  printf("\n");

exit:
  vmi_destroy(vmi);
  return 0;
}