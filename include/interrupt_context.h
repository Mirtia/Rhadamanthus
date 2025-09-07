#ifndef INTERRUPT_CONTEXT_H
#define INTERRUPT_CONTEXT_H

#include <glib-2.0/glib.h>
#include <libvmi/events.h>
#include <libvmi/libvmi.h>
#include <stdbool.h>
#include <stdint.h>

#define INITIAL_CAPACITY 16

/**
 * @brief Breakpoint types for different monitoring categories
 */
typedef enum {
  BP_TYPE_EBPF_PROBE,      ///< eBPF/kprobe function monitoring.
  BP_TYPE_NETFILTER_HOOK,  ///< Netfilter hook registration.
  BP_TYPE_IO_URING,        ///< io_uring system call monitoring.
  BP_TYPE_MAX
} breakpoint_type_t;

/**
 * @brief Forward declaration for breakpoint entry
 */
struct breakpoint_entry;

/**
 * @brief Individual breakpoint entry in the lookup table
 */
typedef struct breakpoint_entry {
  addr_t kaddr;              ///< Kernel virtual address where INT3 is planted.
  uint8_t orig_byte;         ///< Original instruction byte (for restoration).
  const char* symbol_name;   ///< Function symbol name (for logging).
  breakpoint_type_t type;    ///< Type of breakpoint for dispatch.
  void* type_specific_data;  ///< Optional type-specific context data.
  bool active;               ///< Whether this breakpoint is currently active.
} breakpoint_entry_t;

/**
 * @brief Global interrupt context managing all breakpoints
 */
typedef struct {
  breakpoint_entry_t* breakpoints;  ///< Dynamic array of breakpoint entries.
  size_t count;                     ///< Number of active breakpoints.
  size_t capacity;            ///< Allocated capacity of breakpoints array.

  uint64_t total_hits;      ///< Total breakpoint hits.
  uint64_t unhandled_hits;  ///< INT3s that were not covered by breakpoints.
} interrupt_context_t;

/**
 * @brief Initialize global interrupt context.
 * 
 * @param initial_capacity Initial size for breakpoint array.
 * @return interrupt_context_t* Pointer to initialized context else NULL on failure.
 */
interrupt_context_t* interrupt_context_init(size_t initial_capacity);

/**
 * @brief Cleanup and free interrupt context.
 * 
 * This will automatically restore all planted breakpoints before cleanup.
 * 
 * @param ctx Context to cleanup.
 * @param vmi VMI instance for breakpoint restoration.
 */
void interrupt_context_cleanup(interrupt_context_t* ctx, vmi_instance_t vmi);

/**
 * @brief Add a new breakpoint to the monitoring system.
 * 
 * @details Steps:
 * * Translate symbol to virtual address.
 * * Read and save original byte.
 * * Plant INT3 (0xCC) at the address.
 * * Add entry to lookup table.
 * 
 * @param ctx Interrupt context.
 * @param vmi VMI instance.
 * @param symbol_name Kernel symbol to monitor.
 * @param type Breakpoint type for callback dispatch.
 * @param type_data Optional type-specific data.
 * @return int 0 on success else -1 on failure.
 */
int interrupt_context_add_breakpoint(interrupt_context_t* ctx,
                                     vmi_instance_t vmi,
                                     const char* symbol_name,
                                     breakpoint_type_t type, void* type_data);

/**
 * @brief Lookup breakpoint entry by address.
 * 
 * @param ctx Interrupt context.
 * @param kaddr Kernel address to lookup.
 * @return breakpoint_entry_t* Pointer to breakpoint entry else NULL if not found.
 */
breakpoint_entry_t* interrupt_context_lookup_breakpoint(
    interrupt_context_t* ctx, addr_t kaddr);

/**
  * @brief Main interrupt event callback for all INT3 events.
  * 
  * This is the unified callback that is registered with VMI
  * for INT3 interrupt events. It:
  * * Determines which breakpoint was hit.
  * * Dispatches with enum based switching.
  * * Handles breakpoint restoration via single-step.
  * 
  * @param vmi The VMI instance.
  * @param event Interrupt event.
  * @return event_response_t Event response code.
  */
event_response_t interrupt_context_global_callback(vmi_instance_t vmi,
                                                   vmi_event_t* event);

/**
 * @brief Convert breakpoint type to string.
 * 
 * @param type Breakpoint type.
 * @return const char* String representation of the breakpoint.
 */
const char* breakpoint_type_to_str(breakpoint_type_t type);

/**
 * @brief Remove a specific breakpoint by address.
 * 
 * @param ctx Interrupt context.
 * @param vmi VMI instance for byte restoration.
 * @param kaddr Kernel address of breakpoint to remove.
 * @return int 0 on success else -1 on failure.
 */
int interrupt_context_remove_breakpoint(interrupt_context_t* ctx,
                                        vmi_instance_t vmi, addr_t kaddr);

/**
 * @brief Enable/disable a breakpoint without removing it.
 * 
 * @param ctx Interrupt context.
 * @param vmi VMI instance.
 * @param kaddr Kernel address of breakpoint.
 * @param enable True to enable, false to disable.
 * @return int 0 on success else -1 on failure.
 */
int interrupt_context_toggle_breakpoint(interrupt_context_t* ctx,
                                        vmi_instance_t vmi, addr_t kaddr,
                                        bool enable);

/**
 * @brief Print statistics about breakpoint usage.
 * 
 * @param ctx Input interrupt context.
 */
void interrupt_context_print_stats(interrupt_context_t* ctx);

/**
 * @brief Reset interrupt statistics.
 * 
 * @param ctx Interrupt context.
 */
void interrupt_context_reset_stats(interrupt_context_t* ctx);

/**
 * @brief Get count of active breakpoints.
 * 
 * @param ctx Interrupt context.
 * @return size_t Number of active breakpoints.
 */
size_t interrupt_context_get_active_count(interrupt_context_t* ctx);

#endif  // INTERRUPT_CONTEXT_H