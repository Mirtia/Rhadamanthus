#include "event_callbacks/responses/io_uring_ring_write_response.h"
#include <log.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

io_uring_ring_write_data_t* io_uring_ring_write_data_new(
    // NOLINTNEXTLINE
    uint32_t vcpu_id, uint64_t rip, uint64_t rsp, uint64_t cr3,
    uint64_t breakpoint_addr, uint64_t pt_regs_addr,
    unsigned int file_descriptor, unsigned int to_submit,
    unsigned int min_complete, unsigned int flags, uint64_t sig_ptr,
    size_t sigsz, unsigned long user_ip, unsigned long syscall_number) {
  io_uring_ring_write_data_t* data = g_malloc0(sizeof(*data));
  if (!data) {
    log_error("Failed to allocate memory for io_uring ring write data.");
    return NULL;
  }

  data->vcpu_id = vcpu_id;
  data->rip = rip;
  data->rsp = rsp;
  data->cr3 = cr3;
  data->breakpoint_addr = breakpoint_addr;
  data->pt_regs_addr = pt_regs_addr;
  data->file_descriptor = file_descriptor;
  data->to_submit = to_submit;
  data->min_complete = min_complete;
  data->flags = flags;
  data->sig_ptr = sig_ptr;
  data->sigsz = sigsz;
  data->user_ip = user_ip;
  data->syscall_number = syscall_number;

  return data;
}

void io_uring_ring_write_data_free(io_uring_ring_write_data_t* data) {
  if (!data) {
    log_warn("Attempted to free NULL io_uring_ring_write_data_t pointer.");
    return;
  }
  g_free(data);
}

cJSON* io_uring_ring_write_data_to_json(
    const io_uring_ring_write_data_t* data) {
  if (!data) {
    log_error("Invalid io_uring_ring_write_data_t pointer.");
    return NULL;
  }

  cJSON* root = cJSON_CreateObject();
  if (!root) {
    log_error("Failed to create cJSON object for io_uring ring write data.");
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

  // io_uring specific information
  cJSON* io_uring = cJSON_CreateObject();
  if (!io_uring) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(root, "io_uring", io_uring);

  cjson_add_hex_u64(io_uring, "breakpoint_addr", data->breakpoint_addr);
  cjson_add_hex_u64(io_uring, "pt_regs_addr", data->pt_regs_addr);

  // System call information
  cJSON* syscall = cJSON_CreateObject();
  if (!syscall) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(io_uring, "syscall", syscall);
  cJSON_AddNumberToObject(syscall, "number", (double)data->syscall_number);
  cJSON_AddStringToObject(syscall, "name", "__x64_sys_io_uring_enter");
  cjson_add_hex_u64(syscall, "user_ip", data->user_ip);

  // io_uring arguments
  cJSON* arguments = cJSON_CreateObject();
  if (!arguments) {
    cJSON_Delete(root);
    return NULL;
  }
  cJSON_AddItemToObject(io_uring, "arguments", arguments);
  cJSON_AddNumberToObject(arguments, "file_descriptor",
                          (double)data->file_descriptor);
  cJSON_AddNumberToObject(arguments, "to_submit", (double)data->to_submit);
  cJSON_AddNumberToObject(arguments, "min_complete",
                          (double)data->min_complete);

  char flags_str[32];
  (void)snprintf(flags_str, sizeof(flags_str), "0x%08x", data->flags);
  cJSON_AddStringToObject(arguments, "flags", flags_str);

  cjson_add_hex_u64(arguments, "sig_ptr", data->sig_ptr);
  cJSON_AddNumberToObject(arguments, "sigsz", (double)data->sigsz);

  return root;
}