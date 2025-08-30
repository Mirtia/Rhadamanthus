#include "state_callbacks/kernel_code_integrity_check.h"
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define PAGE_SIZE 4096U

/**
 * @brief Hex-encode a binary buffer into a newly allocated string.
 * @param buf   Input bytes.
 * @param len   Input length.
 * @return gchar* Hex string (lowercase). Caller must g_free(). NULL on OOM.
 */
static gchar* hex_encode(const unsigned char* buf, unsigned int len) {
  GString* s = g_string_sized_new(len * 2);
  if (!s)
    return NULL;
  for (unsigned int i = 0; i < len; ++i)
    g_string_append_printf(s, "%02x", buf[i]);
  return g_string_free(s, FALSE); /* transfer ownership of the char* */
}

/**
 * @brief Compute SHA-256 of the guest kernel .text region.
 * @note Assumes the VM is already paused by the caller.
 *
 * @param vmi       LibVMI handle.
 * @param out_hash  Output buffer for digest (EVP_MAX_MD_SIZE).
 * @param out_len   Receives digest length (bytes).
 * @return gboolean TRUE on success, FALSE on failure.
 */
static gboolean compute_kernel_text_sha256(vmi_instance_t vmi,
                                           unsigned char* out_hash,
                                           unsigned int* out_len) {
  addr_t k_start = 0, k_end = 0;

  if (vmi_translate_ksym2v(vmi, "_stext", &k_start) == VMI_FAILURE ||
      vmi_translate_ksym2v(vmi, "_etext", &k_end) == VMI_FAILURE ||
      k_end <= k_start) {
    log_error("Failed to resolve _stext/_etext.");
    return FALSE;
  }

  log_info(".text boundaries: 0x%" PRIx64 " - 0x%" PRIx64, k_start, k_end);

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    log_error("EVP_MD_CTX_new failed.");
    return FALSE;
  }
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    log_error("EVP_DigestInit_ex failed.");
    EVP_MD_CTX_free(ctx);
    return FALSE;
  }

  g_autofree uint8_t* buf = g_malloc(PAGE_SIZE);
  if (!buf) {
    log_error("g_malloc failed for PAGE_SIZE buffer.");
    EVP_MD_CTX_free(ctx);
    return FALSE;
  }

  for (addr_t addr = k_start; addr < k_end; addr += PAGE_SIZE) {
    size_t to_read =
        (addr + PAGE_SIZE > k_end) ? (size_t)(k_end - addr) : PAGE_SIZE;
    size_t bytes_read = 0;
    if (vmi_read_va(vmi, addr, 0 /* kernel ASID */, to_read, buf,
                    &bytes_read) == VMI_FAILURE) {
      log_warn("Failed to read kernel memory at 0x%" PRIx64, addr);
      continue; /* tolerate sparse/guard pages */
    }
    if (bytes_read && EVP_DigestUpdate(ctx, buf, bytes_read) != 1) {
      log_error("EVP_DigestUpdate failed.");
      EVP_MD_CTX_free(ctx);
      return FALSE;
    }
  }

  if (EVP_DigestFinal_ex(ctx, out_hash, out_len) != 1) {
    log_error("EVP_DigestFinal_ex failed.");
    EVP_MD_CTX_free(ctx);
    return FALSE;
  }

  EVP_MD_CTX_free(ctx);
  return TRUE;
}

/**
 * @brief Load a baseline SHA-256 digest from a hex file.
 * @details File must contain a single line of lowercase/uppercase hex, no spaces.
 *
 * @param out_hash  Output buffer for digest.
 * @param out_len   Receives digest length (bytes).
 * @return gboolean TRUE on success, FALSE on failure.
 */
static gboolean load_baseline_hash(unsigned char* out_hash,
                                   unsigned int* out_len) {
  FILE* f = fopen(BASELINE_HASH_FILE, "r");
  if (!f) {
    log_error("Failed to open baseline file: %s", BASELINE_HASH_FILE);
    return FALSE;
  }

  char line[2 * EVP_MAX_MD_SIZE + 8] = {0};
  if (!fgets(line, sizeof(line), f)) {
    log_error("Failed to read baseline hash from: %s", BASELINE_HASH_FILE);
    (void)fclose(f);
    return FALSE;
  }
  (void)fclose(f);

  size_t hexlen = strcspn(line, "\r\n");
  if (hexlen % 2 != 0 || hexlen == 0 || hexlen / 2 > EVP_MAX_MD_SIZE) {
    log_error("Invalid baseline hash format in %s", BASELINE_HASH_FILE);
    return FALSE;
  }

  *out_len = (unsigned int)(hexlen / 2);
  for (size_t i = 0; i < *out_len; ++i) {
    unsigned int byte = 0;
    // TODO: Replace with strtoul. tidy nags again :(.
    if (sscanf(&line[2 * i], "%2x", &byte) != 1) {
      log_error("Invalid hex at position %zu in %s", i, BASELINE_HASH_FILE);
      return FALSE;
    }
    out_hash[i] = (unsigned char)byte;
  }
  return TRUE;
}

/**
 * @brief Kernel code integrity callback: compute SHA-256 over .text and compare to baseline.
 * @note Assumes VM is already paused by the top-level orchestrator.
 *
 * @param vmi     LibVMI instance.
 * @param context Unused.
 * @return VMI_SUCCESS on successful execution (match or mismatch logged), VMI_FAILURE on error.
 */
uint32_t state_kernel_code_integrity_check_callback(vmi_instance_t vmi,
                                                    void* context) {
  (void)context;
  log_info("Executing STATE_KERNEL_CODE_INTEGRITY_CHECK callback.");

  unsigned char observed[EVP_MAX_MD_SIZE];
  unsigned int observed_len = 0;
  if (!compute_kernel_text_sha256(vmi, observed, &observed_len)) {
    return VMI_FAILURE;
  }

  unsigned char baseline[EVP_MAX_MD_SIZE];
  unsigned int baseline_len = 0;
  if (!load_baseline_hash(baseline, &baseline_len)) {
    return VMI_FAILURE;
  }

  const gboolean same_len = (observed_len == baseline_len);
  const gboolean match =
      same_len && (CRYPTO_memcmp(observed, baseline, observed_len) == 0);

  g_autofree gchar* obs_hex = hex_encode(observed, observed_len);
  if (!obs_hex) {
    log_error("Failed to hex-encode observed digest.");
    return VMI_FAILURE;
  }

  if (!match) {
    log_warn(
        "Kernel .text integrity MISMATCH. Observed SHA256=%s (baseline file: "
        "%s)",
        obs_hex, BASELINE_HASH_FILE);
  } else {
    log_info("Kernel .text integrity verified. SHA256=%s", obs_hex);
  }

  log_info("STATE_KERNEL_CODE_INTEGRITY_CHECK callback completed.");

  return VMI_SUCCESS;
}
