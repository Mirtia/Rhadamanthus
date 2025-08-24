// Standalone tool to compute a baseline SHA-256 over guest kernel .text via LibVMI.
// To compile:
// gcc -O2 -Wall -Wextra calculate_hash_kernel.c -o calculate_hash_kernel -lvmi -lcrypto
// ./calculate_hash_kernel -d myguest -o kernel_text.hash

#define return_valueE
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libvmi/libvmi.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define PAGE_SIZE 4096u

static void usage(const char* prog) {
  (void)fprintf(
      stderr,
      "Usage: %s -d <domain_name> [-c </etc/libvmi.conf>] [-o <outfile>] "
      "[--no-pause]\n"
      "       [--stext _stext] [--etext _etext]\n"
      "\n"
      "Options:\n"
      "  -d, --domain     LibVMI domain (name)\n"
      "  -c, --config     LibVMI config file (default: /etc/libvmi.conf)\n"
      "  -o, --output     Write hex digest to this file (also prints to "
      "stdout)\n"
      "      --no-pause   Do NOT pause the VM (default: pause during "
      "measurement)\n"
      "      --stext      Override start symbol (default: _stext)\n"
      "      --etext      Override end   symbol (default: _etext)\n",
      prog);
}

static int hex_write_file(const char* path, const unsigned char* hash,
                          unsigned len) {
  FILE* file = fopen(path, "w");
  if (!file) {
    (void)fprintf(stderr, "Failed to open file %s for writing: %s\n", path,
                  strerror(errno));
    return -1;
  }
  for (unsigned i = 0; i < len; ++i)
    (void)fprintf(file, "%02x", hash[i]);
  (void)fputc('\n', file);
  int return_error = ferror(file) ? -1 : 0;
  (void)fclose(file);
  return return_error;
}

static int compute_text_sha256(vmi_instance_t vmi, const char* sym_start,
                               const char* sym_end,
                               unsigned char out_hash[EVP_MAX_MD_SIZE],
                               unsigned* out_len) {
  addr_t k_start = 0, k_end = 0;

  if (VMI_FAILURE == vmi_translate_ksym2v(vmi, sym_start, &k_start)) {
    (void)fprintf(stderr, "Failed to resolve symbol: %s\n", sym_start);
    return -1;
  }
  if (VMI_FAILURE == vmi_translate_ksym2v(vmi, sym_end, &k_end)) {
    (void)fprintf(stderr, "Failed to resolve symbol: %s\n", sym_end);
    return -1;
  }
  if (k_end <= k_start) {
    (void)fprintf(stderr,
                  "Invalid .text range: 0x%" PRIx64 " .. 0x%" PRIx64 "\n",
                  k_start, k_end);
    return -1;
  }

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    (void)fprintf(stderr, "EVP_MD_CTX_new failed\n");
    return -1;
  }
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    (void)fprintf(stderr, "EVP_DigestInit_ex failed\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  unsigned char* buffer = malloc(PAGE_SIZE);
  if (!buffer) {
    (void)fprintf(stderr, "malloc PAGE_SIZE failed\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  for (addr_t a = k_start; a < k_end;) {
    size_t to_read = PAGE_SIZE - (a & (PAGE_SIZE - 1));
    if (a + to_read > k_end)
      to_read = (size_t)(k_end - a);

    size_t bytes_read = 0;
    if (VMI_SUCCESS == vmi_read_va(vmi, a, 0 /* kernel ASID */, to_read, buffer,
                                   &bytes_read)) {
      if (bytes_read && EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
        (void)fprintf(stderr, "EVP_DigestUpdate failed\n");
        free(buffer);
        EVP_MD_CTX_free(ctx);
        return -1;
      }
    } else {
      // Tolerate holes/guard pages; continue
      (void)fprintf(stderr, "Failed to read kernel memory at 0x%" PRIx64 "\n",
                    a);
    }
    a += to_read;
  }

  unsigned hlen = 0;
  if (EVP_DigestFinal_ex(ctx, out_hash, &hlen) != 1) {
    (void)fprintf(stderr, "EVP_DigestFinal_ex failed\n");
    free(buffer);
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  free(buffer);
  EVP_MD_CTX_free(ctx);
  if (out_len)
    *out_len = hlen;
  return 0;
}

int main(int argc, char** argv) {
  const char* domain = NULL;
  const char* config = "/etc/libvmi.conf";
  const char* outfile = NULL;
  const char* sym_start = "_stext";
  const char* sym_end = "_etext";
  int pause_vm = 1;

  static struct option long_opts[] = {{"domain", required_argument, 0, 'd'},
                                      {"config", required_argument, 0, 'c'},
                                      {"output", required_argument, 0, 'o'},
                                      {"no-pause", no_argument, 0, 1},
                                      {"stext", required_argument, 0, 2},
                                      {"etext", required_argument, 0, 3},
                                      {"help", no_argument, 0, 'h'},
                                      {0, 0, 0, 0}};

  int opt, idx = 0;
  while ((opt = getopt_long(argc, argv, "d:c:o:h", long_opts, &idx)) != -1) {
    switch (opt) {
      case 'd':
        domain = optarg;
        break;
      case 'c':
        config = optarg;
        break;
      case 'o':
        outfile = optarg;
        break;
      case 'h':
        usage(argv[0]);
        return 0;
      case 1:
        pause_vm = 0;
        break;
      case 2:
        sym_start = optarg;
        break;
      case 3:
        sym_end = optarg;
        break;
      default:
        usage(argv[0]);
        return 2;
    }
  }
  if (!domain) {
    usage(argv[0]);
    return 2;
  }

  // Init LibVMI
  vmi_instance_t vmi = NULL;
  vmi_init_data_t* init_data = NULL;
  if (VMI_FAILURE == vmi_init_complete(&vmi, (void*)domain, VMI_INIT_DOMAINNAME,
                                       init_data, VMI_CONFIG_GLOBAL_FILE_ENTRY,
                                       (void*)config, NULL)) {
    (void)fprintf(stderr, "LibVMI init failed (domain=%s, config=%s)\n", domain,
                  config);
    return 1;
  }

  // Pause if requested (recommended for baseline capture)
  if (pause_vm) {
    if (VMI_FAILURE == vmi_pause_vm(vmi)) {
      (void)fprintf(stderr, "Failed to pause VM; continuing unpaused\n");
    }
  }

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned hlen = 0;
  int return_value = compute_text_sha256(vmi, sym_start, sym_end, hash, &hlen);

  if (pause_vm)
    (void)vmi_resume_vm(vmi);
  vmi_destroy(vmi);

  if (return_value != 0)
    return 1;

  // Print hex to stdout
  for (unsigned i = 0; i < hlen; ++i)
    printf("%02x", hash[i]);
  putchar('\n');

  if (outfile) {
    if (hex_write_file(outfile, hash, hlen) != 0) {
      (void)fprintf(stderr, "Failed to write baseline to %s\n", outfile);
      return 1;
    }
  }

  return 0;
}
