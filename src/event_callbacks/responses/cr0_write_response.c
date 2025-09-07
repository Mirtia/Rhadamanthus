#include "event_callbacks/responses/cr0_write_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>

void cjson_add_hex_u64(cJSON* parent, const char* key, uint64_t val) {
  char buffer[20];
  (void)snprintf(buffer, sizeof(buffer), "0x%016" PRIx64, val);
  cJSON_AddStringToObject(parent, key, buffer);
}

void cjson_add_bool(cJSON* parent, const char* key, bool val) {
  cJSON_AddBoolToObject(parent, key, val);
}

void cr0_decode_flags(uint64_t cr0, cr0_flags_t* out_flags) {
  out_flags->PE = (cr0 & CR0_PE) != 0;
  out_flags->WP = (cr0 & CR0_WP) != 0;
  out_flags->AM = (cr0 & CR0_AM) != 0;
  out_flags->CD = (cr0 & CR0_CD) != 0;
  out_flags->PG = (cr0 & CR0_PG) != 0;
}

// NOLINTNEXTLINE
cr0_write_data_t* cr0_write_data_new(uint32_t vcpu_id, uint64_t rip,
                                     uint64_t rsp, uint64_t cr3,
                                     uint64_t cr0_new, bool has_old,
                                     uint64_t cr0_old) {
  cr0_write_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for CR0 write data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;

  data->cr0.new_val = cr0_new;
  data->cr0.has_old = has_old;
  if (has_old) {
    data->cr0.old_val = cr0_old;
  }

  cr0_decode_flags(cr0_new, &data->flags);

  return data;
}

void cr0_write_data_free(cr0_write_data_t* data) {
  if (!data)
    return;
  g_free(data);
}

cJSON* cr0_write_data_to_json(const cr0_write_data_t* data) {
  if (!data) {
    log_error("Invalid cr0_write_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for CR0 write data.");
    return NULL;
  }

  cJSON_AddStringToObject(root, "event", "CR0_WRITE");
  cJSON_AddNumberToObject(root, "vcpu_id", (double)data->vcpu_id);

  cJSON* regs = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "regs", regs);
  cjson_add_hex_u64(regs, "rip", data->rip);
  cjson_add_hex_u64(regs, "rsp", data->rsp);
  cjson_add_hex_u64(regs, "cr3", data->cr3);

  cJSON* cr0 = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "cr0", cr0);
  cjson_add_hex_u64(cr0, "new", data->cr0.new_val);
  if (data->cr0.has_old) {
    cjson_add_hex_u64(cr0, "old", data->cr0.old_val);
  }

  cJSON* flags = cJSON_CreateObject();
  cJSON_AddItemToObject(cr0, "flags", flags);
  cjson_add_bool(flags, "PE", data->flags.PE);
  cjson_add_bool(flags, "WP", data->flags.WP);
  cjson_add_bool(flags, "AM", data->flags.AM);
  cjson_add_bool(flags, "CD", data->flags.CD);
  cjson_add_bool(flags, "PG", data->flags.PG);

  return root;
}
