#include "interrupt_context.h"
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "event_callbacks/ebpf_probe.h"
#include "event_callbacks/io_uring_ring_write.h"
#include "event_callbacks/netfilter_hook_write.h"

interrupt_context_t* interrupt_context_init(size_t initial_capacity) {
  interrupt_context_t* ctx = g_malloc0(sizeof(interrupt_context_t));
  if (!ctx) {
    log_error("Failed to allocate interrupt context.");
    return NULL;
  }

  ctx->breakpoints = g_malloc0(sizeof(breakpoint_entry_t) * initial_capacity);
  if (!ctx->breakpoints) {
    log_error("Failed to allocate breakpoints array.");
    g_free(ctx);
    return NULL;
  }

  // First, I tried to implement a hash table for fast lookups, but for some reason,
  // whether with custom hash function and comparison or not, the keys appeared to be the same
  // but they were not. So, I reverted to a simple array search for now.
  // Fortunately, the list of interrupts is not huge, so performance is not that bad even with O(n).

  ctx->capacity = initial_capacity;
  ctx->count = 0;
  ctx->total_hits = 0;
  ctx->unhandled_hits = 0;

  return ctx;
}

void interrupt_context_cleanup(interrupt_context_t* ctx, vmi_instance_t vmi) {
  if (!ctx)
    return;

  for (size_t i = 0; i < ctx->count; i++) {
    if (ctx->breakpoints[i].active) {
      vmi_write_8_va(vmi, ctx->breakpoints[i].kaddr, 0,
                     &ctx->breakpoints[i].orig_byte);
    }
    g_free(ctx->breakpoints[i].type_specific_data);
    g_free((char*)ctx->breakpoints[i].symbol_name);
  }

  g_free(ctx->breakpoints);
  g_free(ctx);
}

int interrupt_context_add_breakpoint(interrupt_context_t* ctx,
                                     vmi_instance_t vmi,
                                     const char* symbol_name,
                                     breakpoint_type_t type, void* type_data) {
  if (!ctx || !vmi || !symbol_name) {
    log_error("Invalid parameters to add_breakpoint");
    return -1;
  }

  // Translate symbol to kernel virtual address.
  addr_t kaddr = 0;
  if (vmi_translate_ksym2v(vmi, symbol_name, &kaddr) != VMI_SUCCESS) {
    log_debug("Symbol not found: %s", symbol_name);
    return -1;
  }

  // Check for existing breakpoint using simple array search
  for (size_t i = 0; i < ctx->count; i++) {
    if (ctx->breakpoints[i].active && ctx->breakpoints[i].kaddr == kaddr) {
      log_warn("Breakpoint already exists at 0x%" PRIx64, kaddr);
      return -1;
    }
  }

  if (ctx->count >= ctx->capacity) {
    size_t new_capacity = ctx->capacity * 2;
    breakpoint_entry_t* new_breakpoints =
        g_realloc(ctx->breakpoints, sizeof(breakpoint_entry_t) * new_capacity);
    if (!new_breakpoints) {
      log_error("Failed to expand breakpoints array");
      return -1;
    }
    ctx->breakpoints = new_breakpoints;
    ctx->capacity = new_capacity;
  }

  // Read original byte and plant INT3 at the target address.
  uint8_t orig_byte = 0;
  if (vmi_read_8_va(vmi, kaddr, 0, &orig_byte) != VMI_SUCCESS) {
    log_warn(
        "INTERRUPT_CONTEXT: Failed to read original byte at %s @0x%" PRIx64,
        symbol_name, kaddr);
    return -1;
  }

  uint8_t int3 = 0xCC;
  if (vmi_write_8_va(vmi, kaddr, 0, &int3) != VMI_SUCCESS) {
    log_warn("INTERRUPT_CONTEXT: Failed to plant INT3 at %s @0x%" PRIx64,
             symbol_name, kaddr);
    return -1;
  }

  // Populate entry.
  size_t index = ctx->count;
  ctx->breakpoints[index].kaddr = kaddr;
  ctx->breakpoints[index].orig_byte = orig_byte;
  ctx->breakpoints[index].symbol_name = g_strdup(symbol_name);
  ctx->breakpoints[index].type = type;
  ctx->breakpoints[index].type_specific_data = type_data;
  ctx->breakpoints[index].active = true;

  ctx->count++;

  log_info("INTERRUPT_CONTEXT: Added breakpoint: %s @0x%" PRIx64 " (type=%s)",
           symbol_name, kaddr, breakpoint_type_to_str(type));
  return 0;
}

breakpoint_entry_t* interrupt_context_lookup_breakpoint(
    interrupt_context_t* ctx, addr_t kaddr) {
  if (!ctx) {
    log_debug("INTERRUPT_CONTEXT: Context is uninitialized.");
    return NULL;
  }

  // Simple linear search through the breakpoints array :(
  for (size_t i = 0; i < ctx->count; i++) {
    if (ctx->breakpoints[i].active && ctx->breakpoints[i].kaddr == kaddr) {
      log_debug(
          "INTERRUPT_CONTEXT: Found breakpoint at index %zu for address "
          "0x%" PRIx64,
          i, kaddr);
      return &ctx->breakpoints[i];
    }
  }

  log_debug("INTERRUPT_CONTEXT: No breakpoint found at 0x%" PRIx64, kaddr);
  return NULL;
}

/**
 * @brief Handle eBPF probe breakpoint by populating context and calling callback
 *
 * @param vmi VMI instance
 * @param event Event structure
 * @param breakpoint Breakpoint that was hit
 * @return event_response_t Response from the callback
 */
static event_response_t handle_ebpf_breakpoint(vmi_instance_t vmi,
                                               vmi_event_t* event,
                                               breakpoint_entry_t* breakpoint) {
  ebpf_probe_ctx_t* ctx = (ebpf_probe_ctx_t*)breakpoint->type_specific_data;
  if (!ctx) {
    log_error("INTERRUPT_CONTEXT: Missing eBPF context data.");
    return VMI_EVENT_RESPONSE_NONE;
  }

  ctx->kaddr = breakpoint->kaddr;
  ctx->orig = breakpoint->orig_byte;

  void* original_data = event->data;
  event->data = ctx;

  event_response_t result = event_ebpf_probe_callback(vmi, event);

  event->data = original_data;
  return result;
}

/**
 * @brief Handle netfilter hook breakpoint by populating context and calling callback
 *
 * @param vmi VMI instance
 * @param event Event structure
 * @param breakpoint Breakpoint that was hit
 * @return event_response_t Response from the callback
 */
static event_response_t handle_netfilter_breakpoint(
    vmi_instance_t vmi, vmi_event_t* event, breakpoint_entry_t* breakpoint) {
  nf_bp_ctx_t* ctx = (nf_bp_ctx_t*)breakpoint->type_specific_data;
  if (!ctx) {
    log_error("INTERRUPT_CONTEXT: Missing netfilter context data.");
    return VMI_EVENT_RESPONSE_NONE;
  }

  ctx->kaddr = breakpoint->kaddr;
  ctx->orig = breakpoint->orig_byte;

  void* original_data = event->data;
  event->data = ctx;

  event_response_t result = event_netfilter_hook_write_callback(vmi, event);

  event->data = original_data;
  return result;
}

/**
 * @brief Handle io_uring breakpoint by populating context and calling callback
 *
 * @param vmi VMI instance
 * @param event Event structure
 * @param breakpoint Breakpoint that was hit
 * @return event_response_t Response from the callback
 */
static event_response_t handle_io_uring_breakpoint(
    vmi_instance_t vmi, vmi_event_t* event, breakpoint_entry_t* breakpoint) {

  // The breakpoint->type_specific_data contains the io_uring_bp_ctx_t
  // but we need to populate it with the breakpoint info
  io_uring_bp_ctx_t* ctx = (io_uring_bp_ctx_t*)breakpoint->type_specific_data;
  if (!ctx) {
    log_error("INTERRUPT_CONTEXT: Missing io_uring context data.");
    return VMI_EVENT_RESPONSE_NONE;
  }

  ctx->kaddr = breakpoint->kaddr;
  ctx->orig = breakpoint->orig_byte;

  void* original_data = event->data;
  event->data = ctx;

  event_response_t result = event_io_uring_ring_write_callback(vmi, event);

  // Restore original event data
  event->data = original_data;
  return result;
}

event_response_t interrupt_context_global_callback(vmi_instance_t vmi,
                                                   vmi_event_t* event) {
  if (!vmi || !event) {
    log_error(
        "INTERRUPT_CONTEXT: Invalid arguments to global interrupt callback");
    return VMI_EVENT_INVALID;
  }

  interrupt_context_t* ctx = (interrupt_context_t*)event->data;
  if (!ctx) {
    log_error("INTERRUPT_CONTEXT: No interrupt context in event data");
    return VMI_EVENT_INVALID;
  }

  // Get the address where INT3 occurred
  addr_t rip = event->interrupt_event.gla;
  breakpoint_entry_t* breakpoint =
      interrupt_context_lookup_breakpoint(ctx, rip);
  if (!breakpoint) {
    log_debug("Not covered by existing breakpoints (0x%" PRIx64 ")", rip);
    ctx->unhandled_hits++;
    return VMI_EVENT_RESPONSE_NONE;
  }

  ctx->total_hits++;

  switch (breakpoint->type) {
    case BP_TYPE_EBPF_PROBE:
      return handle_ebpf_breakpoint(vmi, event, breakpoint);

    case BP_TYPE_NETFILTER_HOOK:
      return handle_netfilter_breakpoint(vmi, event, breakpoint);

    case BP_TYPE_IO_URING:
      return handle_io_uring_breakpoint(vmi, event, breakpoint);

    default:
      log_warn("Unknown breakpoint type: %d at 0x%" PRIx64, breakpoint->type,
               rip);
      return VMI_EVENT_RESPONSE_NONE;
  }
}

const char* breakpoint_type_to_str(breakpoint_type_t type) {
  switch (type) {
    case BP_TYPE_EBPF_PROBE:
      return "eBPF_PROBE";
    case BP_TYPE_NETFILTER_HOOK:
      return "NETFILTER_HOOK";
    case BP_TYPE_IO_URING:
      return "IO_URING";
    default:
      log_warn("Unknown breakpoint type: %d", type);
      return "UNKNOWN";
  }
}

int interrupt_context_remove_breakpoint(interrupt_context_t* ctx,
                                        vmi_instance_t vmi, addr_t kaddr) {
  if (!ctx || !vmi) {
    log_debug("Context or VMI is uninitialized.");
    return -1;
  }

  breakpoint_entry_t* breakpoint =
      interrupt_context_lookup_breakpoint(ctx, kaddr);
  if (!breakpoint || !breakpoint->active) {
    return -1;
  }

  // Restore original add
  if (vmi_write_8_va(vmi, kaddr, 0, &breakpoint->orig_byte) != VMI_SUCCESS) {
    log_warn("INTERRUPT_CONTEXT: Failed to restore original byte at 0x%" PRIx64,
             kaddr);
    return -1;
  }

  // Mark as inactive and cleanup
  breakpoint->active = false;
  g_free((char*)breakpoint->symbol_name);
  g_free(breakpoint->type_specific_data);
  breakpoint->symbol_name = NULL;
  breakpoint->type_specific_data = NULL;

  // No hash table removal needed
  log_info("Removed breakpoint at 0x%" PRIx64, kaddr);
  return 0;
}

int interrupt_context_toggle_breakpoint(interrupt_context_t* ctx,
                                        vmi_instance_t vmi, addr_t kaddr,
                                        bool enable) {
  if (!ctx || !vmi) {
    log_debug("Context or VMI is uninitialized.");
    return -1;
  }

  // Find breakpoint using simple array search.
  breakpoint_entry_t* breakpoint = NULL;
  for (size_t i = 0; i < ctx->count; i++) {
    if (ctx->breakpoints[i].kaddr == kaddr) {
      breakpoint = &ctx->breakpoints[i];
      break;
    }
  }

  if (!breakpoint) {
    log_debug("No breakpoint found at 0x%" PRIx64, kaddr);
    return -1;
  }

  // Skip if already in desired state
  if (breakpoint->active == enable) {
    return 0;
  }

  if (enable && !breakpoint->active) {
    // Plant INT3
    uint8_t int3 = 0xCC;
    if (vmi_write_8_va(vmi, kaddr, 0, &int3) != VMI_SUCCESS) {
      return -1;
    }
    breakpoint->active = true;
  } else if (!enable && breakpoint->active) {
    // Restore original byte
    if (vmi_write_8_va(vmi, kaddr, 0, &breakpoint->orig_byte) != VMI_SUCCESS) {
      return -1;
    }
    breakpoint->active = false;
  }

  return 0;
}

void interrupt_context_print_stats(interrupt_context_t* ctx) {
  if (!ctx) {
    log_error("Interrupt context is uninitialized.");
    return;
  }

  log_info("Active breakpoints: %zu/%zu",
           interrupt_context_get_active_count(ctx), ctx->capacity);
  log_info("Total hits: %" PRIu64, ctx->total_hits);
  log_info("Unhandled hits: %" PRIu64, ctx->unhandled_hits);

  for (size_t i = 0; i < ctx->count; i++) {
    if (ctx->breakpoints[i].active) {
      log_info("  %s @0x%" PRIx64 " (%s)", ctx->breakpoints[i].symbol_name,
               ctx->breakpoints[i].kaddr,
               breakpoint_type_to_str(ctx->breakpoints[i].type));
    }
  }
}

void interrupt_context_reset_stats(interrupt_context_t* ctx) {
  if (!ctx) {
    return;
  }
  // Stats are cumulative, so just reset the counters.
  ctx->total_hits = 0;
  ctx->unhandled_hits = 0;
}

size_t interrupt_context_get_active_count(interrupt_context_t* ctx) {
  if (!ctx) {
    return 0;
  }

  size_t active_count = 0;
  for (size_t i = 0; i < ctx->count; i++) {
    if (ctx->breakpoints[i].active) {
      active_count++;
    }
  }
  return active_count;
}