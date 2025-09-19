#include "utils.h"

#include <inttypes.h>
#include <log.h>

event_response_t log_error_and_queue_response_event(const char* event_name,
                                                    event_task_id_t event_type,
                                                    int error_code,
                                                    const char* message) {
  log_error("%s", message);

  if (json_serializer_is_global_initialized()) {
    struct response* error_resp = create_error_response(
        EVENT, (void*)(uintptr_t)event_type, error_code, message);
    if (error_resp) {
      json_serializer_queue_global(event_name, error_resp);
    }
  }
  return VMI_EVENT_INVALID;
}

int log_error_and_queue_response_task(const char* task_name,
                                      state_task_id_t task_type, int error_code,
                                      const char* message) {
  log_error("%s", message);

  if (json_serializer_is_global_initialized()) {
    struct response* error_resp = create_error_response(
        EVENT, (void*)(uintptr_t)task_type, error_code, message);
    if (error_resp) {
      json_serializer_queue_global(task_name, error_resp);
    }
  }
  return VMI_FAILURE;
}

event_response_t log_error_and_queue_response_interrupt(
    const char* interrupt_name, interrupt_task_id_t interrupt_type,
    int error_code, const char* message) {
  log_error("%s", message);

  if (json_serializer_is_global_initialized()) {
    struct response* error_resp = create_error_response(
        INTERRUPT, (void*)(uintptr_t)interrupt_type, error_code, message);
    if (error_resp) {
      json_serializer_queue_global(interrupt_name, error_resp);
    }
  }
  return VMI_EVENT_INVALID;
}

event_response_t log_success_and_queue_response_event(
    const char* event_name, event_task_id_t event_type, void* data_ptr,
    void (*data_free_func)(void*)) {
  if (json_serializer_is_global_initialized()) {
    struct response* success_resp =
        create_success_response(EVENT, (void*)(uintptr_t)event_type, data_ptr);
    if (success_resp) {
      json_serializer_queue_global(event_name, success_resp);
      return VMI_EVENT_RESPONSE_NONE;
    }
    log_error("Failed to create success response for %s event.", event_name);
    if (data_free_func && data_ptr) {
      data_free_func(data_ptr);
    }
    return VMI_EVENT_INVALID;
  }

  if (data_free_func && data_ptr) {
    data_free_func(data_ptr);
  }
  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t log_success_and_queue_response_interrupt(
    const char* interrupt_name, interrupt_task_id_t interrupt_type,
    void* data_ptr, void (*data_free_func)(void*)) {

  if (json_serializer_is_global_initialized()) {
    struct response* success_resp = create_success_response(
        INTERRUPT, (void*)(uintptr_t)interrupt_type, data_ptr);
    if (success_resp) {
      json_serializer_queue_global(interrupt_name, success_resp);
      return VMI_EVENT_RESPONSE_NONE;
    }
    log_error("Failed to create success response for %s event.",
              interrupt_name);
    if (data_free_func && data_ptr) {
      data_free_func(data_ptr);
    }
    return VMI_EVENT_INVALID;
  }

  if (data_free_func && data_ptr) {
    data_free_func(data_ptr);
  }
  return VMI_EVENT_RESPONSE_NONE;
}

int log_success_and_queue_response_task(const char* task_name,
                                        state_task_id_t task_type,
                                        void* data_ptr,
                                        void (*data_free_func)(void*)) {
  if (json_serializer_is_global_initialized()) {
    struct response* success_resp =
        create_success_response(STATE, (void*)(uintptr_t)task_type, data_ptr);
    if (success_resp) {
      json_serializer_queue_global(task_name, success_resp);
      return VMI_SUCCESS;
    }
    log_error("Failed to create success response for %s task.", task_name);
    if (data_free_func && data_ptr) {
      data_free_func(data_ptr);
    }
    return VMI_FAILURE;
  }

  if (data_free_func && data_ptr) {
    data_free_func(data_ptr);
  }
  return VMI_SUCCESS;
}

uint32_t get_kernel_text_section_range(vmi_instance_t vmi, addr_t* start_addr,
                                       addr_t* end_addr) {
  if (!vmi) {
    log_debug("VMI instance is uninitialized.");
    return VMI_FAILURE;
  }

  if ((vmi_translate_ksym2v(vmi, "_stext", start_addr) == VMI_FAILURE ||
       vmi_translate_ksym2v(vmi, "_etext", end_addr) == VMI_FAILURE)) {
    log_debug("Failed to resolve kernel .text boundaries.");
    return VMI_FAILURE;
  }

  return VMI_SUCCESS;
}

bool is_in_kernel_text(vmi_instance_t vmi, addr_t addr) {

  if (!vmi) {
    log_debug("VMI instance is uninitialized.");
    return false;
  }

  addr_t start_addr = 0, end_addr = 0;

  if (get_kernel_text_section_range(vmi, &start_addr, &end_addr) !=
      VMI_SUCCESS) {
    log_debug("Unable to get kernel text section range for address check.");
    return false;
  }
  // Kernel bounds: [start_addr, end_addr)
  return (addr >= start_addr && addr < end_addr);
}

void log_vcpu_state(vmi_instance_t vmi, uint32_t vcpu_id, addr_t kaddr,
                    const char* context) {
  if (!vmi) {
    log_warn("log_vcpu_state: Invalid VMI instance");
    return;
  }

  reg_t rip = 0, rflags = 0;
  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    log_warn("log_vcpu_state: Failed to get RIP for vCPU %u", vcpu_id);
    rip = 0;
  }

  if (vmi_get_vcpureg(vmi, &rflags, RFLAGS, vcpu_id) != VMI_SUCCESS) {
    log_warn("log_vcpu_state: Failed to get RFLAGS for vCPU %u", vcpu_id);
    rflags = 0;
  }

  uint8_t byte_at_kaddr = 0;
  if (kaddr != 0) {
    if (vmi_read_8_va(vmi, kaddr, 0, &byte_at_kaddr) != VMI_SUCCESS) {
      log_warn("log_vcpu_state: Failed to read byte at 0x%" PRIx64, kaddr);
      // Sentinel value.
      byte_at_kaddr = 0xFF;
    }

    unsigned int tf_flag = (unsigned int)((rflags >> 8) & 1);

    if (kaddr != 0) {
      log_info("%s state: RIP=0x%" PRIx64 " TF=%u byte@0x%" PRIx64
               "=0x%02x vCPU=%u",
               context ? context : "VCPU", (uint64_t)rip, tf_flag, kaddr,
               byte_at_kaddr, vcpu_id);
    } else {
      log_info("%s state: RIP=0x%" PRIx64 " TF=%u vCPU=%u",
               context ? context : "VCPU", (uint64_t)rip, tf_flag, vcpu_id);
    }
  }
}

void cjson_add_hex_u32(cJSON* parent, const char* key, uint32_t val) {
  char buf[2 + 8 + 1];  // "0x" + 8 hex digits + NUL
  (void)snprintf(buf, sizeof(buf), "0x%08" PRIx32, val);
  cJSON_AddStringToObject(parent, key, buf);
}

void cjson_add_hex_u64(cJSON* parent, const char* key, uint64_t val) {
  char buffer[20];
  (void)snprintf(buffer, sizeof(buffer), "0x%016" PRIx64, val);
  cJSON_AddStringToObject(parent, key, buffer);
}

void cjson_add_hex_addr(cJSON* parent, const char* key, addr_t val) {
  char buffer[20];
  (void)snprintf(buffer, sizeof(buffer), "0x%016" PRIx64, (uint64_t)val);
  cJSON_AddStringToObject(parent, key, buffer);
}

void cjson_add_bool(cJSON* parent, const char* key, bool val) {
  cJSON_AddBoolToObject(parent, key, val);
}
