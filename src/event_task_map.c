#include "event_task_map.h"
#include <log.h>
#include <stddef.h>
#include "event_callbacks/code_section_modify.h"
#include "event_callbacks/cr0_write.h"
#include "event_callbacks/ebpf_map_update.h"
#include "event_callbacks/ftrace_hook.h"
#include "event_callbacks/idt_write.h"
#include "event_callbacks/io_uring_ring_write.h"
#include "event_callbacks/kallsyms_table_write.h"
#include "event_callbacks/msr_write.h"
#include "event_callbacks/netfilter_hook_write.h"
#include "event_callbacks/page_table_modification.h"
#include "event_callbacks/syscall_table_write.h"

// Event creation functions
static vmi_event_t* create_event_ftrace_hook(vmi_instance_t vmi);
static vmi_event_t* create_event_syscall_table_write(vmi_instance_t vmi);
static vmi_event_t* create_event_idt_write(vmi_instance_t vmi);
static vmi_event_t* create_event_cr0_write(vmi_instance_t vmi);
static vmi_event_t* create_event_page_table_modification(vmi_instance_t vmi);
static vmi_event_t* create_event_netfilter_hook_write(vmi_instance_t vmi);
static vmi_event_t* create_event_msr_write(vmi_instance_t vmi);
static vmi_event_t* create_event_code_section_modify(vmi_instance_t vmi);
static vmi_event_t* create_event_io_uring_ring_write(vmi_instance_t vmi);
static vmi_event_t* create_event_ebpf_map_update(vmi_instance_t vmi);
static vmi_event_t* create_event_kallsyms_table_write(vmi_instance_t vmi);

// Helper functions for event setup
static vmi_event_t* setup_memory_event(
    addr_t addr, vmi_mem_access_t access_type,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*));
static vmi_event_t* setup_register_event(
    reg_t reg, vmi_reg_access_t access_type,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*));

// Event task mapping structure
typedef struct {
  event_task_id_t task_id;
  vmi_event_t* (*create_func)(vmi_instance_t vmi);
  event_response_t (*callback)(vmi_instance_t, vmi_event_t*);
  const char* description;
} event_task_map_entry_t;

// Event task mapping table
static const event_task_map_entry_t event_task_map[] = {
    {.task_id = EVENT_FTRACE_HOOK,
     .create_func = create_event_ftrace_hook,
     .callback = event_ftrace_hook_callback,
     .description = "Ftrace function hooking detection"},
    {.task_id = EVENT_SYSCALL_TABLE_WRITE,
     .create_func = create_event_syscall_table_write,
     .callback = event_syscall_table_write_callback,
     .description = "System call table modification detection"},
    {.task_id = EVENT_IDT_WRITE,
     .create_func = create_event_idt_write,
     .callback = event_idt_write_callback,
     .description = "Interrupt descriptor table modification detection"},
    {.task_id = EVENT_CR0_WRITE,
     .create_func = create_event_cr0_write,
     .callback = event_cr0_write_callback,
     .description = "CR0 control register modification detection"},
    {.task_id = EVENT_PAGE_TABLE_MODIFICATION,
     .create_func = create_event_page_table_modification,
     .callback = event_page_table_modification_callback,
     .description = "Page table entry modification detection"},
    {.task_id = EVENT_NETFILTER_HOOK_WRITE,
     .create_func = create_event_netfilter_hook_write,
     .callback = event_netfilter_hook_write_callback,
     .description = "Netfilter hook registration/modification detection"},
    {.task_id = EVENT_MSR_WRITE,
     .create_func = create_event_msr_write,
     .callback = event_msr_write_callback,
     .description = "Model Specific Register modification detection"},
    {.task_id = EVENT_CODE_SECTION_MODIFY,
     .create_func = create_event_code_section_modify,
     .callback = event_code_section_modify_callback,
     .description = "Kernel code section modification detection"},
    {.task_id = EVENT_IO_URING_RING_WRITE,
     .create_func = create_event_io_uring_ring_write,
     .callback = event_io_uring_ring_write_callback,
     .description = "io_uring ring buffer modification detection"},
    {.task_id = EVENT_EBPF_MAP_UPDATE,
     .create_func = create_event_ebpf_map_update,
     .callback = event_ebpf_map_update_callback,
     .description = "eBPF map update detection"},
    {.task_id = EVENT_KALLSYMS_TABLE_WRITE,
     .create_func = create_event_kallsyms_table_write,
     .callback = event_kallsyms_table_write_callback,
     .description = "Kernel symbol table modification detection"}};

static const size_t event_task_map_size =
    sizeof(event_task_map) / sizeof(event_task_map[0]);

static vmi_event_t* setup_memory_event(
    //NOLINTNEXTLINE
    addr_t addr, vmi_mem_access_t access_type,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*)) {
  vmi_event_t* event = g_malloc0(sizeof(vmi_event_t));

  event->version = VMI_EVENTS_VERSION;
  event->type = VMI_EVENT_MEMORY;
  event->mem_event.gfn =
      addr >> 12;                // Convert address to GFN (Guest Frame Number)
  event->mem_event.generic = 0;  // Not using generic events
  event->mem_event.in_access = access_type;
  event->callback = callback;

  return event;
}

static vmi_event_t* setup_register_event(
    // NOLINTNEXTLINE
    reg_t reg, vmi_reg_access_t access_type,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*)) {
  vmi_event_t* event = g_malloc0(sizeof(vmi_event_t));

  event->version = VMI_EVENTS_VERSION;
  event->type = VMI_EVENT_REGISTER;
  event->reg_event.reg = reg;
  event->reg_event.in_access = access_type;
  event->callback = callback;

  return event;
}

// Event creation implementations

static vmi_event_t* create_event_ftrace_hook(vmi_instance_t vmi) {
  // Monitor writes to ftrace_ops structures
  // This requires identifying ftrace registration functions
  addr_t ftrace_ops_addr = 0;
  if (vmi_translate_ksym2v(vmi, "ftrace_ops_list", &ftrace_ops_addr) !=
      VMI_SUCCESS) {
    log_warn(
        "Failed to resolve ftrace_ops_list symbol for ftrace hook monitoring");
    return NULL;
  }

  return setup_memory_event(ftrace_ops_addr, VMI_MEMACCESS_W,
                            event_ftrace_hook_callback);
}

static vmi_event_t* create_event_syscall_table_write(vmi_instance_t vmi) {
  addr_t sys_call_table = 0;
  if (vmi_translate_ksym2v(vmi, "sys_call_table", &sys_call_table) !=
      VMI_SUCCESS) {
    log_error("Failed to resolve sys_call_table symbol");
    return NULL;
  }

  // Monitor entire syscall table (assume 512 syscalls * 8 bytes each)
  size_t syscall_table_size = 512 * sizeof(addr_t);
  return setup_memory_event(sys_call_table, VMI_MEMACCESS_W,
                            event_syscall_table_write_callback);
}

static vmi_event_t* create_event_idt_write(vmi_instance_t vmi) {
  // Monitor IDT table - get IDTR base address
  uint64_t idtr_base = 0;
  uint32_t vcpu_count = vmi_get_num_vcpus(vmi);

  if (vcpu_count > 0) {
    if (vmi_get_vcpureg(vmi, &idtr_base, IDTR_BASE, 0) != VMI_SUCCESS) {
      log_error("Failed to get IDTR base address");
      return NULL;
    }
  } else {
    log_error("No VCPUs available");
    return NULL;
  }

  // IDT has 256 entries, each 16 bytes
  size_t idt_size = (size_t)(256) * 16;
  return setup_memory_event(idtr_base, VMI_MEMACCESS_W,
                            event_idt_write_callback);
}

static vmi_event_t* create_event_cr0_write(vmi_instance_t vmi) {
  return setup_register_event(CR0, VMI_REGACCESS_W, event_cr0_write_callback);
}

static vmi_event_t* create_event_page_table_modification(vmi_instance_t vmi) {
  // This is complex - we need to monitor page table writes
  // For now, monitor writes to the current CR3 (page directory)
  uint64_t cr3 = 0;
  if (vmi_get_vcpureg(vmi, &cr3, CR3, 0) != VMI_SUCCESS) {
    log_error("Failed to get CR3 register");
    return NULL;
  }

  // Monitor page table area (approximate)
  size_t pt_size = 0x1000;  // 4KB page
  return setup_memory_event(cr3, VMI_MEMACCESS_W,
                            event_page_table_modification_callback);
}

static vmi_event_t* create_event_netfilter_hook_write(vmi_instance_t vmi) {
  // Monitor netfilter hook registration
  addr_t nf_hooks = 0;
  if (vmi_translate_ksym2v(vmi, "nf_hooks", &nf_hooks) != VMI_SUCCESS) {
    log_warn("Failed to resolve nf_hooks symbol");
    // Try alternative symbol
    if (vmi_translate_ksym2v(vmi, "nf_hook_entries", &nf_hooks) !=
        VMI_SUCCESS) {
      log_error("Failed to repsolve netfilter hooks symbol");
      return NULL;
    }
  }

  // Monitor netfilter hooks area
  // TODO: Confirm 13 protocol families * 5 hook points
  size_t nf_hooks_size = 13UL * 5 * sizeof(addr_t);
  return setup_memory_event(nf_hooks, VMI_MEMACCESS_W,
                            event_netfilter_hook_write_callback);
}

static vmi_event_t* create_event_msr_write(vmi_instance_t vmi) {
  // Monitor all MSR writes
  return setup_register_event(MSR_ALL, VMI_REGACCESS_W,
                              event_msr_write_callback);
}

static vmi_event_t* create_event_code_section_modify(vmi_instance_t vmi) {
  addr_t text_start = 0, text_end = 0;
  if (vmi_translate_ksym2v(vmi, "_text", &text_start) != VMI_SUCCESS ||
      vmi_translate_ksym2v(vmi, "_etext", &text_end) != VMI_SUCCESS) {
    log_error("Failed to resolve kernel text section boundaries");
    return NULL;
  }

  size_t text_size = text_end - text_start;
  return setup_memory_event(text_start, VMI_MEMACCESS_W,
                            event_code_section_modify_callback);
}

static vmi_event_t* create_event_io_uring_ring_write(vmi_instance_t vmi) {
  (void)vmi;
  // Monitor io_uring operations - this is complex as it's per-process
  // For now, we'll monitor common io_uring structures
  // This would need more sophisticated implementation in practice
  log_warn(
      "io_uring monitoring requires process-specific ring buffer tracking");

  // Placeholder - would need to track io_uring_setup syscalls and monitor created rings
  return NULL;
}

static vmi_event_t* create_event_ebpf_map_update(vmi_instance_t vmi) {
  // Monitor eBPF map operations - complex as maps are dynamically allocated
  // Would need to hook bpf_map_update_elem function or similar
  log_warn("eBPF map monitoring requires dynamic map tracking");

  // Placeholder - would need to track BPF syscalls and monitor created maps
  return NULL;
}

int register_all_event_tasks(event_handler_t* event_handler) {
  if (!event_handler) {
    log_error("Event handler is NULL");
    return -1;
  }

  int registered_count = 0;

  for (size_t i = 0; i < event_task_map_size; i++) {
    const event_task_map_entry_t* entry = &event_task_map[i];

    log_info("Registering event task: %s", entry->description);

    vmi_event_t* event = entry->create_func(event_handler->vmi);
    if (event) {
      event_handler_register_event_task(event_handler, entry->task_id, event,
                                        entry->callback);
      registered_count++;
      log_info("Successfully registered: %s", entry->description);
    } else {
      log_warn("Failed to create event for: %s", entry->description);
    }
  }

  log_info("Registered %d out of %zu event tasks", registered_count,
           event_task_map_size);
  return registered_count;
}

int register_event_task_by_id(event_handler_t* event_handler,
                              event_task_id_t task_id) {
  if (!event_handler) {
    log_error("Event handler is NULL");
    return -1;
  }

  for (size_t i = 0; i < event_task_map_size; i++) {
    const event_task_map_entry_t* entry = &event_task_map[i];

    if (entry->task_id == task_id) {
      log_info("Registering specific event task: %s", entry->description);

      vmi_event_t* event = entry->create_func(event_handler->vmi);
      if (event) {
        event_handler_register_event_task(event_handler, entry->task_id, event,
                                          entry->callback);
        log_info("Successfully registered: %s", entry->description);
        return 1;
      }

      log_error("Failed to create event for: %s", entry->description);
      return -1;
    }
  }

  log_error("Event task ID %d not found in mapping table", task_id);
  return -1;
}

void list_available_event_tasks(void) {
  log_info("Available event tasks:");

  for (size_t i = 0; i < event_task_map_size; i++) {
    const event_task_map_entry_t* entry = &event_task_map[i];
    log_info("  %d: %s - %s", entry->task_id,
             event_task_id_to_str(entry->task_id), entry->description);
  }
}

static vmi_event_t* create_event_kallsyms_table_write(vmi_instance_t vmi) {
  vmi_event_t* event = g_malloc0(sizeof(vmi_event_t));

  addr_t kallsyms_addresses = 0;
  if (vmi_translate_ksym2v(vmi, "kallsyms_addresses", &kallsyms_addresses) !=
      VMI_SUCCESS) {
    log_error("Failed to resolve kallsyms_addresses symbol");
    g_free(event);
    return NULL;
  }

  // Monitor kallsyms tables (approximate size)
  size_t kallsyms_size = 0x100000;  // 1MB approximate
  SETUP_MEM_EVENT(event, kallsyms_addresses, VMI_MEMACCESS_W,
                  event_kallsyms_table_write_callback, kallsyms_size);
  return event;
}