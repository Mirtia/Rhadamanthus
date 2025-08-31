#include "event_task_map.h"
#include <inttypes.h>
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

#define PAGE_SIZE 4096  ///< X86_64 page size

// Event creation functions, early declarations for the map later on.
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

static vmi_event_t* setup_memory_event(
    addr_t addr, vmi_mem_access_t access_type,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*));
static vmi_event_t* setup_register_event(
    reg_t reg, vmi_reg_access_t access_type,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*));

/**
 * @brief Event task mapping structure
 */
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
     .callback = event_kallsyms_write_callback,
     .description = "Kernel symbol table modification detection"}};

static const size_t event_task_map_size =
    sizeof(event_task_map) / sizeof(event_task_map[0]);

static vmi_event_t* setup_memory_event(
    //NOLINTNEXTLINE
    addr_t addr, vmi_mem_access_t access_type,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*)) {

  vmi_event_t* event = g_new0(vmi_event_t, 1);
  if (event == NULL) {
    log_error("Failed to allocate memory for vmi_event_t");
    return NULL;
  }

  // TODO: Confirm correctness
  event->version = VMI_EVENTS_VERSION;
  event->type = VMI_EVENT_MEMORY;
  event->mem_event.gfn = addr >> 12;
  event->mem_event.generic = 0;
  event->mem_event.in_access = access_type;
  event->callback = callback;

  return event;
}

static vmi_event_t* setup_register_event(
    // NOLINTNEXTLINE
    reg_t reg, vmi_reg_access_t access_type,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*)) {
  // g_new is encouraged for type safety
  vmi_event_t* event = g_new0(vmi_event_t, 1);
  if (event == NULL) {
    log_error("Failed to allocate memory for vmi_event_t");
    return NULL;
  }

  event->version = VMI_EVENTS_VERSION;
  event->type = VMI_EVENT_REGISTER;
  event->reg_event.reg = reg;
  event->reg_event.in_access = access_type;
  event->callback = callback;

  return event;
}

static vmi_event_t* create_event_ftrace_hook(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  addr_t ftrace_ops_addr = 0;
  // Just monitor writes to ftrace_ops_list.
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
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  addr_t sys_call_table = 0;
  if (vmi_translate_ksym2v(vmi, "sys_call_table", &sys_call_table) !=
      VMI_SUCCESS) {
    log_error("Failed to resolve sys_call_table symbol");
    return NULL;
  }

  size_t syscall_table_size = 512 * sizeof(addr_t);
  return setup_memory_event(sys_call_table, VMI_MEMACCESS_W,
                            event_syscall_table_write_callback);
}

static vmi_event_t* create_event_idt_write(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
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

  size_t idt_size = (size_t)(256) * 16;
  return setup_memory_event(idtr_base, VMI_MEMACCESS_W,
                            event_idt_write_callback);
}

static vmi_event_t* create_event_cr0_write(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  return setup_register_event(CR0, VMI_REGACCESS_W, event_cr0_write_callback);
}

static vmi_event_t* create_event_page_table_modification(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  // Hypervisor shit
  // Get current CR3 (kernel CR3 on vCPU 0 is fine for a single baseline).
  uint64_t cr3 = 0;
  if (vmi_get_vcpureg(vmi, &cr3, CR3, 0) != VMI_SUCCESS) {
    log_error("PT watch: failed to read CR3");
    return NULL;
  }
  addr_t pml4_pa = (addr_t)(cr3 & ~0xFFFULL);

  /* Create the memory write event on the PML4 page (GFN = PA >> 12). */
  vmi_event_t* event = setup_memory_event(
      pml4_pa, VMI_MEMACCESS_W, event_page_table_modification_callback);
  if (!event)
    return NULL;

  /* Allocate and seed the context with an initial snapshot (if possible). */
  pt_watch_ctx_t* ctx = g_malloc0(sizeof(*ctx));
  if (!ctx) {
    log_error("PT watch: failed to allocate context");
    g_free(event);
    return NULL;
  }
  ctx->pml4_pa = pml4_pa;
  if (vmi_read_pa(vmi, ctx->pml4_pa, sizeof(ctx->shadow), ctx->shadow, NULL) ==
      VMI_SUCCESS) {
    ctx->shadow_valid = 1;
    log_info("PT watch: initial PML4 snapshot taken @0x%lx",
             (unsigned long)ctx->pml4_pa);
  } else {
    log_warn(
        "PT watch: could not snapshot PML4 @0x%lx now; will prime on first "
        "write",
        (unsigned long)ctx->pml4_pa);
  }

  event->data = ctx;
  return event;
}

/**
 * @brief Create the breakpoint on nf_register_net_hook / nf_register_net_hooks.
 *
 * Replaces the old memory-write watcher. Returns the first successfully
 * registered BREAKPOINT event; caller registers it with LibVMI and keeps it alive.
 */
static vmi_event_t* create_event_netfilter_hook_write(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }

  const char* candidates[] = {"nf_register_net_hook", "nf_register_net_hooks"};

  for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
    addr_t kaddr = 0;
    if (vmi_translate_ksym2v(vmi, candidates[i], &kaddr) != VMI_SUCCESS ||
        !kaddr) {
      log_debug("Symbol not found: %s", candidates[i]);
      continue;
    }

    uint8_t orig = 0;
    if (vmi_read_8_va(vmi, kaddr, 0, &orig) != VMI_SUCCESS) {
      log_warn("Failed reading first byte at %s @0x%" PRIx64, candidates[i],
               (uint64_t)kaddr);
      continue;
    }

    uint8_t cc = 0xCC;
    if (vmi_write_8_va(vmi, kaddr, 0, &cc) != VMI_SUCCESS) {
      log_warn("Failed planting INT3 at %s @0x%" PRIx64, candidates[i],
               (uint64_t)kaddr);
      continue;
    }

    // Allocate context and breakpoint event
    nf_bp_ctx_t* ctx = (nf_bp_ctx_t*)g_malloc0(sizeof(*ctx));
    if (!ctx) {
      log_error("Failed to allocate nf_bp_ctx_t");
      // Try to restore the byte we just patched (best-effort)
      {
        uint8_t val = orig;
        (void)vmi_write_8_va(vmi, kaddr, 0, &val);
      }
      continue;
    }
    ctx->kaddr = kaddr;
    ctx->orig = orig;
    ctx->symname = candidates[i];

    vmi_event_t* bp_evt = (vmi_event_t*)g_malloc0(sizeof(*bp_evt));
    if (!bp_evt) {
      log_error("Failed to allocate vmi_event_t");
      {
        uint8_t val = orig;
        (void)vmi_write_8_va(vmi, kaddr, 0, &val);
      }
      g_free(ctx);
      continue;
    }

    memset(bp_evt, 0, sizeof(*bp_evt));
    bp_evt->version = VMI_EVENTS_VERSION;
    bp_evt->type = VMI_EVENT_SINGLESTEP;
    bp_evt->callback =
        event_netfilter_hook_write_callback;  // exported name used in map
    bp_evt->data = ctx;

    if (vmi_register_event(vmi, bp_evt) != VMI_SUCCESS) {
      log_warn("Failed to register BREAKPOINT event for %s", candidates[i]);
      // Restore original byte on failure
      {
        uint8_t val = orig;
        (void)vmi_write_8_va(vmi, kaddr, 0, &val);
      }
      g_free(ctx);
      g_free(bp_evt);
      continue;
    }

    log_info("Planted INT3 on %s @0x%" PRIx64, candidates[i], (uint64_t)kaddr);
    return bp_evt;
  }

  log_error("No netfilter registration symbols could be hooked.");
  return NULL;
}

static vmi_event_t* create_event_msr_write(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  // Monitor all MSR writes
  (void)vmi;
  return setup_register_event(MSR_ALL, VMI_REGACCESS_W,
                              event_msr_write_callback);
}

static vmi_event_t* create_event_code_section_modify(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  addr_t text_start = 0, text_end = 0;
  if (vmi_translate_ksym2v(vmi, "_text", &text_start) != VMI_SUCCESS ||
      vmi_translate_ksym2v(vmi, "_etext", &text_end) != VMI_SUCCESS) {
    log_error("Failed to resolve kernel text section boundaries");
    return NULL;
  }

  size_t text_size = text_end - text_start;
  size_t page_count = (text_size + PAGE_SIZE - 1) / PAGE_SIZE;

  for (size_t i = 0; i < page_count; ++i) {
    addr_t page_addr = text_start + i * PAGE_SIZE;
    vmi_event_t* event = setup_memory_event(page_addr, VMI_MEMACCESS_W,
                                            event_code_section_modify_callback);

    if (!event || vmi_register_event(vmi, event) != VMI_SUCCESS) {
      log_error("Failed to register code section modify event at 0x%" PRIx64,
                page_addr);
      if (event)
        g_free(event);
    }
  }

  log_info("Registered write monitoring on %zu pages of kernel .text section",
           page_count);

  // You can return NULL here if nothing else needs to hold the event object
  return NULL;
}

static vmi_event_t* create_event_io_uring_ring_write(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  addr_t kaddr = 0;
  const char* chosen_sym = NULL;

  /* Try common symbol names: x86_64 first, then generic. */
  const char* candidates[] = {
      "__x64_sys_io_uring_enter",
      "io_uring_enter",
  };

  for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
    if (vmi_translate_ksym2v(vmi, candidates[i], &kaddr) == VMI_SUCCESS &&
        kaddr) {
      chosen_sym = candidates[i];
      break;
    }
  }
  if (!chosen_sym) {
    log_warn(
        "io_uring: could not resolve io_uring_enter symbol on this kernel; "
        "skipping.");
    return NULL;
  }

  vmi_event_t* event = g_malloc0(sizeof(*event));
  if (!event) {
    log_error("io_uring: failed to allocate vmi_event_t");
    return NULL;
  }

  io_uring_bp_ctx_t* ctx = g_malloc0(sizeof(*ctx));
  if (!ctx) {
    log_error("io_uring: failed to allocate breakpoint context");
    g_free(event);
    return NULL;
  }
  ctx->kaddr = kaddr;
  ctx->symname = chosen_sym;

  // Save original first byte and patch INT3 (0xCC).
  if (vmi_read_8_va(vmi, kaddr, 0, &ctx->orig) != VMI_SUCCESS) {
    log_error("io_uring: failed to read original byte @0x%" PRIx64,
              (uint64_t)kaddr);
    g_free(ctx);
    g_free(event);
    return NULL;
  }
  uint8_t int3 = 0xCC;
  if (vmi_write_8_va(vmi, kaddr, 0, &int3) != VMI_SUCCESS) {
    log_error("io_uring: failed to write INT3 @0x%" PRIx64
              " (text may be write-protected).",
              (uint64_t)kaddr);
    g_free(ctx);
    g_free(event);
    return NULL;
  }

  event->version = VMI_EVENTS_VERSION;
  event->type = VMI_EVENT_SINGLESTEP;
  event->data = ctx;

  return event;
}

static vmi_event_t* create_event_ebpf_map_update(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  // Monitor eBPF map operations - complex as maps are dynamically allocated
  // Would need to hook bpf_map_update_elem function or similar
  log_warn("eBPF map monitoring requires dynamic map tracking");

  return NULL;
}

int register_all_event_tasks(event_handler_t* event_handler) {
  // Preconditions
  if (!event_handler) {
    log_error("Event handler is NULL");
    return -1;
  }

  int registered_count = 0;

  for (size_t i = 0; i < event_task_map_size; ++i) {
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

  for (size_t i = 0; i < event_task_map_size; ++i) {
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
  if (event == NULL) {
    log_error("Failed to allocate memory for vmi_event_t");
    return NULL;
  }

  addr_t kallsyms_addresses = 0;
  if (vmi_translate_ksym2v(vmi, "kallsyms_addresses", &kallsyms_addresses) !=
      VMI_SUCCESS) {
    log_error("Failed to resolve kallsyms_addresses symbol");
    g_free(event);
    return NULL;
  }

  size_t kallsyms_size = 0;

  addr_t kallsyms_num_syms = 0;
  if (vmi_translate_ksym2v(vmi, "kallsyms_num_syms", &kallsyms_num_syms) ==
      VMI_SUCCESS) {
    uint32_t num_syms = 0;
    if (vmi_read_va(vmi, kallsyms_num_syms, 0, sizeof(uint32_t), &num_syms,
                    NULL) == VMI_SUCCESS &&
        num_syms > 0) {
      kallsyms_size = num_syms * sizeof(addr_t);
      log_info("Resolved %u kallsyms entries (total size: %zu bytes)", num_syms,
               kallsyms_size);
    } else {
      log_warn(
          "Failed to read kallsyms_num_syms, falling back to default size.");
    }
  } else {
    log_warn(
        "Could not resolve kallsyms_num_syms, falling back to default size.");
  }

  if (kallsyms_size == 0) {
    // Note: This is a constant out of ass.
    kallsyms_size = 0x100000;
    log_info("Using default kallsyms_addresses size: %zu bytes", kallsyms_size);
  }

  SETUP_MEM_EVENT(event, kallsyms_addresses, VMI_MEMACCESS_W,
                  event_kallsyms_write_callback, kallsyms_size);

  return event;
}
