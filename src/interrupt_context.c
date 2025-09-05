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

  ctx->addr_to_index = g_hash_table_new(g_direct_hash, g_direct_equal);
  if (!ctx->addr_to_index) {
    log_error("Failed to create address lookup table.");
    g_free(ctx->breakpoints);
    g_free(ctx);
    return NULL;
  }

  ctx->capacity = initial_capacity;
  ctx->count = 0;
  ctx->total_hits = 0;
  ctx->unhandled_hits = 0;

  return ctx;
}

void interrupt_context_cleanup(interrupt_context_t* ctx, vmi_instance_t vmi) {
  if (!ctx)
    return;

  // Restore all planted breakpoints
  for (size_t i = 0; i < ctx->count; i++) {
    if (ctx->breakpoints[i].active) {
      // Write out original bytes.
      vmi_write_8_va(vmi, ctx->breakpoints[i].kaddr, 0,
                     &ctx->breakpoints[i].orig_byte);
    }
    g_free(ctx->breakpoints[i].type_specific_data);
    g_free((char*)ctx->breakpoints[i].symbol_name);
  }

  g_free(ctx->breakpoints);
  g_hash_table_destroy(ctx->addr_to_index);

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

  // Translate symbol to address
  addr_t kaddr = 0;
  if (vmi_translate_ksym2v(vmi, symbol_name, &kaddr) != VMI_SUCCESS) {
    log_debug("Symbol not found: %s", symbol_name);
    return -1;
  }

  if (g_hash_table_lookup(ctx->addr_to_index, GSIZE_TO_POINTER(kaddr)) !=
      NULL) {
    log_warn("Breakpoint already exists at 0x%" PRIx64, kaddr);
    return -1;
  }

  // Expand hash table like a vector, no need to overcomplicate this.
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

  // Read original byte and store it in the context structure later on.
  uint8_t orig_byte = 0;
  if (vmi_read_8_va(vmi, kaddr, 0, &orig_byte) != VMI_SUCCESS) {
    log_warn("Failed to read original byte at %s @0x%" PRIx64, symbol_name,
             kaddr);
    return -1;
  }

  // Plant INT3.
  uint8_t int3 = 0xCC;
  if (vmi_write_8_va(vmi, kaddr, 0, &int3) != VMI_SUCCESS) {
    log_warn("Failed to plant INT3 at %s @0x%" PRIx64, symbol_name, kaddr);
    return -1;
  }

  size_t index = ctx->count;
  ctx->breakpoints[index].kaddr = kaddr;
  ctx->breakpoints[index].orig_byte = orig_byte;
  ctx->breakpoints[index].symbol_name = g_strdup(symbol_name);
  ctx->breakpoints[index].type = type;
  ctx->breakpoints[index].type_specific_data = type_data;
  ctx->breakpoints[index].active = true;

  g_hash_table_insert(ctx->addr_to_index, GSIZE_TO_POINTER(kaddr),
                      GSIZE_TO_POINTER(index));

  ctx->count++;

  log_info("Added breakpoint: %s @0x%" PRIx64 " (type=%d)", symbol_name, kaddr,
           type);

  return 0;
}

breakpoint_entry_t* interrupt_context_lookup_breakpoint(
    interrupt_context_t* ctx, addr_t kaddr) {
  if (!ctx) {
    log_debug("Context is uninitialized.");
    return NULL;
  }

  gpointer index_ptr =
      g_hash_table_lookup(ctx->addr_to_index, GSIZE_TO_POINTER(kaddr));
  if (!index_ptr) {
    return NULL;
  }

  size_t index = GPOINTER_TO_SIZE(index_ptr);
  if (index >= ctx->count || !ctx->breakpoints[index].active) {
    return NULL;
  }

  breakpoint_entry_t* breakpoint = &ctx->breakpoints[index];
  return breakpoint;
}

/**
 * @brief Type-specific dispatch handlers
 */
static event_response_t handle_ebpf_breakpoint(vmi_instance_t vmi,
                                               vmi_event_t* event,
                                               breakpoint_entry_t* breakpoint) {
  void* original_data = event->data;
  event->data = breakpoint->type_specific_data;

  event_response_t result = event_ebpf_probe_callback(vmi, event);

  event->data = original_data;
  return result;
}

static event_response_t handle_netfilter_breakpoint(
    vmi_instance_t vmi, vmi_event_t* event, breakpoint_entry_t* breakpoint) {
  void* original_data = event->data;
  event->data = breakpoint->type_specific_data;

  event_response_t result = event_netfilter_hook_write_callback(vmi, event);

  event->data = original_data;
  return result;
}

static event_response_t handle_io_uring_breakpoint(
    vmi_instance_t vmi, vmi_event_t* event, breakpoint_entry_t* breakpoint) {
  void* original_data = event->data;
  event->data = breakpoint->type_specific_data;

  event_response_t result = event_io_uring_ring_write_callback(vmi, event);

  event->data = original_data;
  return result;
}

event_response_t interrupt_context_global_callback(vmi_instance_t vmi,
                                                   vmi_event_t* event) {
  if (!vmi || !event) {
    log_error("Invalid arguments to global interrupt callback");
    return VMI_EVENT_INVALID;
  }

  interrupt_context_t* ctx = (interrupt_context_t*)event->data;
  if (!ctx) {
    log_error("No interrupt context in event data");
    return VMI_EVENT_INVALID;
  }

  // Get the address where INT3 occurred
  addr_t rip = event->interrupt_event.gla;

  breakpoint_entry_t* breakpoint =
      interrupt_context_lookup_breakpoint(ctx, rip);
  if (!breakpoint) {
    log_debug("Not covered by existing breakpoints.");
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
      log_warn("Unknwon breakpoint type: %d", type);
      return "UNKNOWN";
  }
}

// Missing functions that should be added to interrupt_context.c

/**
 * @brief Remove a specific breakpoint by address
 */
int interrupt_context_remove_breakpoint(interrupt_context_t* ctx,
                                        vmi_instance_t vmi, addr_t kaddr) {
  if (!ctx || !vmi) {
    return -1;
  }

  breakpoint_entry_t* breakpoint =
      interrupt_context_lookup_breakpoint(ctx, kaddr);
  if (!breakpoint || !breakpoint->active) {
    return -1;
  }

  // Restore original byte
  if (vmi_write_8_va(vmi, kaddr, 0, &breakpoint->orig_byte) != VMI_SUCCESS) {
    log_warn("Failed to restore original byte at 0x%" PRIx64, kaddr);
    return -1;
  }

  // Mark as inactive and cleanup
  breakpoint->active = false;
  g_free((char*)breakpoint->symbol_name);
  g_free(breakpoint->type_specific_data);
  breakpoint->symbol_name = NULL;
  breakpoint->type_specific_data = NULL;

  // Remove from hash table
  g_hash_table_remove(ctx->addr_to_index, GSIZE_TO_POINTER(kaddr));

  log_info("Removed breakpoint at 0x%" PRIx64, kaddr);
  return 0;
}

/**
 * @brief Enable/disable a breakpoint without removing it
 */
int interrupt_context_toggle_breakpoint(interrupt_context_t* ctx,
                                        vmi_instance_t vmi, addr_t kaddr,
                                        bool enable) {
  if (!ctx || !vmi) {
    log_debug("Context or VMI is uninitialized.");
    return -1;
  }

  gpointer index_ptr =
      g_hash_table_lookup(ctx->addr_to_index, GSIZE_TO_POINTER(kaddr));
  if (!index_ptr) {
    return -1;
  }
  
  size_t index = GPOINTER_TO_SIZE(index_ptr);
  if (index >= ctx->count) {
    return -1;
  }

  breakpoint_entry_t* breakpoint = &ctx->breakpoints[index];

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
