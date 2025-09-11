#include "state_callbacks/responses/kallsyms_symbols_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

kallsyms_symbols_state_data_t* kallsyms_symbols_state_data_new(void) {
  kallsyms_symbols_state_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for kallsyms symbols state data.");
    return NULL;
  }

  data->symbols = g_array_new(FALSE, FALSE, sizeof(kallsyms_symbol_info_t));
  if (!data->symbols) {
    kallsyms_symbols_state_data_free(data);
    log_error("Failed to allocate array for kallsyms symbols state data.");
    return NULL;
  }

  return data;
}

void kallsyms_symbols_state_data_free(kallsyms_symbols_state_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL kallsyms_symbols_state_data_t pointer.");
    return;
  }

  if (data->symbols) {
    for (guint i = 0; i < data->symbols->len; i++) {
      kallsyms_symbol_info_t* symbol =
          &g_array_index(data->symbols, kallsyms_symbol_info_t, i);
      g_free(symbol->address);
      g_free(symbol->type);
      g_free(symbol->name);
      g_free(symbol->module);
    }
    g_array_free(data->symbols, TRUE);
  }

  // Free filter strings
  g_free(data->summary.filters.name_regex);
  g_free(data->summary.filters.module_regex);

  g_free(data);
}

void kallsyms_symbols_state_add_symbol(kallsyms_symbols_state_data_t* data,
                                       const char* address, const char* type,
                                       const char* name, const char* module) {
  if (!data || !data->symbols)
    return;

  kallsyms_symbol_info_t symbol = {
      .address = address ? g_strdup(address) : g_strdup("0x0"),
      .type = type ? g_strdup(type) : g_strdup("?"),
      .name = name ? g_strdup(name) : g_strdup("unknown"),
      .module = module ? g_strdup(module) : NULL};

  g_array_append_val(data->symbols, symbol);
}

void kallsyms_symbols_state_set_summary(
    kallsyms_symbols_state_data_t* data, uint32_t total_symbols,
    uint32_t returned_symbols, int32_t kptr_restrict, const char* name_regex,
    const char* module_regex, int32_t max_symbols, uint32_t reachable,
    uint32_t zero_addr, uint32_t name_fail, uint32_t addr_fail,
    uint32_t in_text, uint32_t outside_text) {
  if (!data)
    return;

  data->summary.total_symbols = total_symbols;
  data->summary.returned_symbols = returned_symbols;
  data->summary.kptr_restrict = kptr_restrict;

  // Set filters
  data->summary.filters.name_regex =
      name_regex ? g_strdup(name_regex) : g_strdup("");
  data->summary.filters.module_regex =
      module_regex ? g_strdup(module_regex) : g_strdup("");
  data->summary.filters.max_symbols = max_symbols;

  // Set statistics
  data->summary.statistics.reachable = reachable;
  data->summary.statistics.zero_addr = zero_addr;
  data->summary.statistics.name_fail = name_fail;
  data->summary.statistics.addr_fail = addr_fail;
  data->summary.statistics.in_text = in_text;
  data->summary.statistics.outside_text = outside_text;
}

cJSON* kallsyms_symbols_state_data_to_json(
    const kallsyms_symbols_state_data_t* data) {
  if (!data) {
    log_error("Invalid kallsyms_symbols_state_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for kallsyms symbols state data.");
    return NULL;
  }

  // Symbols array
  cJSON* symbols_array = cJSON_CreateArray();
  if (!symbols_array) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "symbols", symbols_array);

  for (guint i = 0; i < data->symbols->len; i++) {
    kallsyms_symbol_info_t* symbol =
        &g_array_index(data->symbols, kallsyms_symbol_info_t, i);

    cJSON* symbol_obj = cJSON_CreateObject();
    if (!symbol_obj) {
      cJSON_Delete(root);
      return NULL;
    }

    cJSON_AddStringToObject(symbol_obj, "address", symbol->address);
    cJSON_AddStringToObject(symbol_obj, "type", symbol->type);
    cJSON_AddStringToObject(symbol_obj, "name", symbol->name);
    if (symbol->module) {
      cJSON_AddStringToObject(symbol_obj, "module", symbol->module);
    } else {
      cJSON_AddNullToObject(symbol_obj, "module");
    }

    cJSON_AddItemToArray(symbols_array, symbol_obj);
  }

  // Summary section
  cJSON* summary = cJSON_CreateObject();
  if (!summary) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "summary", summary);

  cJSON_AddNumberToObject(summary, "total_symbols",
                          (double)data->summary.total_symbols);
  cJSON_AddNumberToObject(summary, "returned_symbols",
                          (double)data->summary.returned_symbols);
  cJSON_AddNumberToObject(summary, "kptr_restrict",
                          (double)data->summary.kptr_restrict);

  // Filters section
  cJSON* filters = cJSON_CreateObject();
  if (!filters) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(summary, "filters", filters);

  cJSON_AddStringToObject(filters, "name_regex",
                          data->summary.filters.name_regex);
  cJSON_AddStringToObject(filters, "module_regex",
                          data->summary.filters.module_regex);
  if (data->summary.filters.max_symbols >= 0) {
    cJSON_AddNumberToObject(filters, "max_symbols",
                            (double)data->summary.filters.max_symbols);
  } else {
    cJSON_AddNullToObject(filters, "max_symbols");
  }

  // Statistics section
  cJSON* statistics = cJSON_CreateObject();
  if (!statistics) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(summary, "statistics", statistics);

  cJSON_AddNumberToObject(statistics, "reachable",
                          (double)data->summary.statistics.reachable);
  cJSON_AddNumberToObject(statistics, "zero_addr",
                          (double)data->summary.statistics.zero_addr);
  cJSON_AddNumberToObject(statistics, "name_fail",
                          (double)data->summary.statistics.name_fail);
  cJSON_AddNumberToObject(statistics, "addr_fail",
                          (double)data->summary.statistics.addr_fail);
  cJSON_AddNumberToObject(statistics, "in_text",
                          (double)data->summary.statistics.in_text);
  cJSON_AddNumberToObject(statistics, "outside_text",
                          (double)data->summary.statistics.outside_text);

  return root;
}
