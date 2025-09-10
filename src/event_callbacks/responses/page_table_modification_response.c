#include "event_callbacks/responses/page_table_modification_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

page_table_modification_data_t* page_table_modification_data_new(
    // NOLINTNEXTLINE
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t pml4_pa) {
  page_table_modification_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for page table modification data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->pml4_pa = pml4_pa;

  data->modifications =
      g_array_new(FALSE, FALSE, sizeof(pt_entry_modification_t));
  if (!data->modifications) {
    g_free(data);
    log_error("Failed to allocate modifications array.");
    return NULL;
  }

  return data;
}

void page_table_modification_add_entry(page_table_modification_data_t* data,
                                       uint32_t index, uint64_t old_entry,
                                       uint64_t new_entry, bool old_present,
                                       bool new_present, bool old_writable,
                                       bool new_writable, bool old_user,
                                       bool new_user, bool old_noexec,
                                       bool new_noexec) {
  if (!data || !data->modifications) {
    log_error("Invalid page table modification data.");
    return;
  }

  pt_entry_modification_t mod = {.index = index,
                                 .old_entry = old_entry,
                                 .new_entry = new_entry,
                                 .old_flags = {.present = old_present,
                                               .writable = old_writable,
                                               .user = old_user,
                                               .noexec = old_noexec},
                                 .new_flags = {.present = new_present,
                                               .writable = new_writable,
                                               .user = new_user,
                                               .noexec = new_noexec}};

  g_array_append_val(data->modifications, mod);
}

void page_table_modification_data_free(page_table_modification_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL page_table_modification_data_t pointer.");
    return;
  }

  if (data->modifications) {
    g_array_free(data->modifications, TRUE);
  }

  g_free(data);
}

cJSON* page_table_modification_data_to_json(
    const page_table_modification_data_t* data) {
  if (!data) {
    log_error("Invalid page_table_modification_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error(
        "Failed to create cJSON object for page table modification data.");
    return NULL;
  }

  // vcpu_id as a JSON number
  cJSON_AddNumberToObject(root, "vcpu_id", (double)data->vcpu_id);

  // Register values
  cJSON* regs = cJSON_CreateObject();
  if (!regs) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "regs", regs);
  cjson_add_hex_u64(regs, "rip", data->rip);
  cjson_add_hex_u64(regs, "rsp", data->rsp);
  cjson_add_hex_u64(regs, "cr3", data->cr3);

  // Page table information
  cJSON* page_table = cJSON_CreateObject();
  if (!page_table) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "page_table", page_table);
  cjson_add_hex_u64(page_table, "pml4_pa", data->pml4_pa);

  // Modifications array
  cJSON* modifications = cJSON_CreateArray();
  if (!modifications) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(page_table, "modifications", modifications);

  for (guint i = 0; i < data->modifications->len; i++) {
    pt_entry_modification_t* mod =
        &g_array_index(data->modifications, pt_entry_modification_t, i);

    cJSON* mod_obj = cJSON_CreateObject();
    if (!mod_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddNumberToObject(mod_obj, "index", (double)mod->index);
    cjson_add_hex_u64(mod_obj, "old_entry", mod->old_entry);
    cjson_add_hex_u64(mod_obj, "new_entry", mod->new_entry);

    // Old flags
    cJSON* old_flags = cJSON_CreateObject();
    if (!old_flags) {
      cJSON_Delete(mod_obj);
      cJSON_Delete(root);
      return NULL;
    }
    cjson_add_bool(old_flags, "present", mod->old_flags.present);
    cjson_add_bool(old_flags, "writable", mod->old_flags.writable);
    cjson_add_bool(old_flags, "user", mod->old_flags.user);
    cjson_add_bool(old_flags, "noexec", mod->old_flags.noexec);
    cJSON_AddItemToObject(mod_obj, "old_flags", old_flags);

    // New flags
    cJSON* new_flags = cJSON_CreateObject();
    if (!new_flags) {
      cJSON_Delete(mod_obj);
      cJSON_Delete(root);
      return NULL;
    }
    cjson_add_bool(new_flags, "present", mod->new_flags.present);
    cjson_add_bool(new_flags, "writable", mod->new_flags.writable);
    cjson_add_bool(new_flags, "user", mod->new_flags.user);
    cjson_add_bool(new_flags, "noexec", mod->new_flags.noexec);
    cJSON_AddItemToObject(mod_obj, "new_flags", new_flags);

    cJSON_AddItemToArray(modifications, mod_obj);
  }

  return root;
}