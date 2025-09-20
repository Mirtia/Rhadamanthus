#include "event_task_map.h"
#include <inttypes.h>
#include <log.h>
#include <stddef.h>
#include "event_callbacks/code_section_modify.h"
#include "event_callbacks/cr0_write.h"
#include "event_callbacks/ebpf_tracepoint.h"
#include "event_callbacks/ftrace_hook.h"
#include "event_callbacks/idt_write.h"
#include "event_callbacks/io_uring_ring_write.h"
#include "event_callbacks/kallsyms_table_write.h"
#include "event_callbacks/kprobe.h"
#include "event_callbacks/msr_write.h"
#include "event_callbacks/network_monitor.h"
#include "event_callbacks/page_table_modification.h"
#include "event_callbacks/syscall_table_write.h"
#include "utils.h"

#define PAGE_SIZE 4096  ///< x86_64 page size
#define PAGE_SHIFT 12
#define PAGE_MASK (~(PAGE_SIZE - 1ULL))

// Event creation functions, early declarations for the map later on.
static GPtrArray* create_event_ftrace_hook(vmi_instance_t vmi);
static GPtrArray* create_event_syscall_table_write(vmi_instance_t vmi);
static GPtrArray* create_event_idt_write(vmi_instance_t vmi);
static GPtrArray* create_event_cr0_write(vmi_instance_t vmi);
static GPtrArray* create_event_page_table_modification(vmi_instance_t vmi);
static GPtrArray* create_event_msr_write(vmi_instance_t vmi);
static GPtrArray* create_event_code_section_modify(vmi_instance_t vmi);
static GPtrArray* create_event_kallsyms_table_write(vmi_instance_t vmi);

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
  GPtrArray* (*create_func)(vmi_instance_t vmi);
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
    {.task_id = EVENT_MSR_WRITE,
     .create_func = create_event_msr_write,
     .callback = event_msr_write_callback,
     .description = "MSR modification detection"},
    {.task_id = EVENT_CODE_SECTION_MODIFY,
     .create_func = create_event_code_section_modify,
     .callback = event_code_section_modify_callback,
     .description = "Kernel code section modification detection"},
    {.task_id = EVENT_KALLSYMS_TABLE_WRITE,
     .create_func = create_event_kallsyms_table_write,
     .callback = event_kallsyms_write_callback,
     .description = "Kernel symbol table modification detection"}};

static const size_t event_task_map_size =
    sizeof(event_task_map) / sizeof(event_task_map[0]);

/**
* @brief Set up a memory event object.
* 
* @param phy_addr The input physical adress.
* @param access_type The type of access (e.g VMI_MEMACCESS_W for write)
* @param callback The callback function for the memory event.
* @return vmi_event_t* A new event object.
*/
static vmi_event_t* setup_memory_event(
    // NOLINTNEXTLINE
    addr_t phy_addr, vmi_mem_access_t access_type,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*)) {
  // g_new is encouraged for type safety
  vmi_event_t* event = g_new0(vmi_event_t, 1);
  if (event == NULL) {
    log_error("Failed to allocate memory for vmi_event_t");
    return NULL;
  }

  event->version = VMI_EVENTS_VERSION;
  event->type = VMI_EVENT_MEMORY;
  // This assumes that the address has been translated to physical, responsiblity of the caller.
  // Shift by 12 to get guest frame number (physical page number).
  event->mem_event.gfn = phy_addr >> 12;
  // out_access is ignored.
  event->mem_event.in_access = access_type;
  event->callback = callback;

  // Debug: Log the memory event setup
  log_debug("Memory event setup: phy_addr=0x%" PRIx64 " gfn=%" PRIu64
            " access_type=%d",
            phy_addr, event->mem_event.gfn, access_type);
  return event;
}

/**
 * @brief Set up a register event object.
 * 
 * @param reg The register to monitor (e.g CR0)
 * @param access_type The type of access (e.g VMI_REGACCESS_W for write)
 * @param callback The callback function for the register event.
 * @return vmi_event_t* A new event object.
 */
static vmi_event_t* setup_register_event(
    // NOLINTNEXTLINE
    reg_t reg, vmi_reg_access_t access_type,
    event_response_t (*callback)(vmi_instance_t, vmi_event_t*)) {
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

static GPtrArray* create_event_ftrace_hook(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  addr_t ftrace_ops_addr = 0;
  addr_t ftrace_ops_phy_addr = 0;
  // For now, we monitor writes to ftrace_ops_list.
  if (vmi_translate_ksym2v(vmi, "ftrace_ops_list", &ftrace_ops_addr) !=
      VMI_SUCCESS) {
    log_warn(
        "Failed to resolve ftrace_ops_list symbol for ftrace hook monitoring");
    return NULL;
  }

  if (vmi_translate_kv2p(vmi, ftrace_ops_addr, &ftrace_ops_phy_addr) !=
      VMI_SUCCESS) {
    log_warn(
        "Failed to translate ftrace_ops_list VA->PA for ftrace hook "
        "monitoring");
    return NULL;
  }

  vmi_event_t* event = setup_memory_event(ftrace_ops_phy_addr, VMI_MEMACCESS_W,
                                          event_ftrace_hook_callback);
  if (!event) {
    log_error("Failed to create ftrace hook memory event");
    return NULL;
  }

  GPtrArray* events = g_ptr_array_new_with_free_func(g_free);
  if (!events) {
    log_error("Failed to create events array for ftrace hook");
    g_free(event);  // Clean up the event
    return NULL;
  }

  g_ptr_array_add(events, event);
  return events;
}

static GPtrArray* create_event_syscall_table_write(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }

  addr_t syscall_table_addr = 0;
  addr_t syscall_table_phy_addr = 0;

  if (vmi_translate_ksym2v(vmi, "sys_call_table", &syscall_table_addr) !=
      VMI_SUCCESS) {
    log_error("Failed to resolve syscall_table_addr symbol");
    return NULL;
  }

  if (vmi_translate_kv2p(vmi, syscall_table_addr, &syscall_table_phy_addr) !=
      VMI_SUCCESS) {
    log_error("Failed to translate syscall_table_addr VA->PA");
    return NULL;
  }

  vmi_event_t* event =
      setup_memory_event(syscall_table_phy_addr, VMI_MEMACCESS_W,
                         event_syscall_table_write_callback);
  if (!event) {
    log_error("Failed to create syscall table write memory event");
    return NULL;
  }

  GPtrArray* events = g_ptr_array_new_with_free_func(g_free);
  g_ptr_array_add(events, event);

  log_info("Created syscall table write monitoring event at PA: 0x%" PRIx64,
           syscall_table_phy_addr);

  return events;
}

static GPtrArray* create_event_idt_write(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }

  const uint32_t vcpu_count = vmi_get_num_vcpus(vmi);
  if (vcpu_count == 0) {
    log_error("No VCPUs available");
    return NULL;
  }

  GPtrArray* events = g_ptr_array_new_with_free_func(g_free);
  // Some IDT pages may be shared between vCPUs, so deduplicate by GFN.
  GArray* seen_gfns = g_array_new(FALSE, FALSE, sizeof(addr_t));

  for (uint32_t vcpu = 0; vcpu < vcpu_count; ++vcpu) {
    uint64_t idtr_base = 0;
    uint64_t idtr_limit = 0;

    if (vmi_get_vcpureg(vmi, &idtr_base, IDTR_BASE, vcpu) != VMI_SUCCESS) {
      log_warn("IDT: failed to read IDTR_BASE on vCPU %u", vcpu);
      continue;
    }
    if (vmi_get_vcpureg(vmi, &idtr_limit, IDTR_LIMIT, vcpu) != VMI_SUCCESS) {
      idtr_limit = PAGE_SIZE - 1;
    }

    const addr_t idt_va = (addr_t)idtr_base;
    const size_t idt_size = (size_t)idtr_limit + 1;

    const addr_t first_page_va = idt_va & PAGE_MASK;
    const size_t first_off = (size_t)(idt_va & (PAGE_SIZE - 1));
    const size_t page_count =
        (first_off + idt_size + PAGE_SIZE - 1) / PAGE_SIZE;

    for (size_t i = 0; i < page_count; ++i) {
      const addr_t page_va = first_page_va + i * PAGE_SIZE;

      addr_t page_pa = 0;
      if (vmi_translate_kv2p(vmi, page_va, &page_pa) != VMI_SUCCESS ||
          !page_pa) {
        log_warn("IDT: VA to PA failed (vCPU %u, VA=0x%lx)", vcpu,
                 (unsigned long)page_va);
        continue;
      }

      const addr_t gfn = page_pa >> PAGE_SHIFT;

      bool already = false;
      for (guint j = 0; j < seen_gfns->len; ++j) {
        if (g_array_index(seen_gfns, addr_t, j) == gfn) {
          already = true;
          break;
        }
      }
      if (already)
        continue;

      g_array_append_val(seen_gfns, gfn);

      vmi_event_t* event = setup_memory_event(page_pa, VMI_MEMACCESS_W,
                                              event_idt_write_callback);
      if (!event) {
        g_array_free(seen_gfns, TRUE);
        g_ptr_array_free(events, TRUE);
        return NULL;
      }

      g_ptr_array_add(events, event);

      log_info(
          "IDT: monitoring vCPU %u IDT page: VA=0x%lx PA=0x%lx GFN=0x%lx "
          "(base=0x%llx, limit=0x%llx)",
          vcpu, (unsigned long)page_va, (unsigned long)page_pa,
          (unsigned long)gfn, (unsigned long long)idtr_base,
          (unsigned long long)idtr_limit);
    }
  }

  g_array_free(seen_gfns, TRUE);

  if (events->len == 0) {
    g_ptr_array_free(events, TRUE);
    log_warn("IDT: no pages were registered (no translations succeeded).");
    return NULL;
  }

  return events;
}

static GPtrArray* create_event_cr0_write(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  vmi_event_t* event =
      setup_register_event(CR0, VMI_REGACCESS_W, event_cr0_write_callback);
  if (!event) {
    return NULL;
  }

  GPtrArray* events = g_ptr_array_new_with_free_func(g_free);
  g_ptr_array_add(events, event);
  return events;
}

static GPtrArray* create_event_page_table_modification(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }

  // Get kernel CR3 from vCPU 0 (single-baseline... extend later if needed)
  uint64_t cr3 = 0;
  if (vmi_get_vcpureg(vmi, &cr3, CR3, 0) != VMI_SUCCESS) {
    log_error("PT watch: failed to read CR3");
    return NULL;
  }

  // Extract PML4 base physical address: CR3[63:12]
  const addr_t pml4_pa = (addr_t)(cr3 & PAGE_MASK);

  // Create the memory event on the PML4 page (writes only)
  vmi_event_t* event = setup_memory_event(
      pml4_pa, VMI_MEMACCESS_W, event_page_table_modification_callback);

  if (!event) {
    log_error("PT watch: failed to create memory event");
    return NULL;
  }

  // Allocate and seed the watcher context with an initial snapshot (best-effort)
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

  GPtrArray* events = g_ptr_array_new_with_free_func(NULL);
  g_ptr_array_add(events, event);
  return events;
}

static GPtrArray* create_event_msr_write(vmi_instance_t vmi) {
  // Preconditions
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  // Monitor all MSR writes (MSR_ALL).
  (void)vmi;
  vmi_event_t* event =
      setup_register_event(MSR_ALL, VMI_REGACCESS_W, event_msr_write_callback);

  if (!event) {
    return NULL;
  }

  GPtrArray* events = g_ptr_array_new_with_free_func(g_free);
  g_ptr_array_add(events, event);
  return events;
}

static GPtrArray* create_event_code_section_modify(vmi_instance_t vmi) {
  // Preconditions
  // TODO:
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
    addr_t page_phy_addr = 0;
    if (vmi_translate_kv2p(vmi, page_addr, &page_phy_addr) != VMI_SUCCESS ||
        !page_phy_addr) {
      log_warn("Failed to translate text section page VA->PA @0x%" PRIx64,
               page_addr);
      continue;
    }
    vmi_event_t* event = setup_memory_event(page_phy_addr, VMI_MEMACCESS_W,
                                            event_code_section_modify_callback);

    if (!event) {
      log_error("Failed to setup code section modify event at 0x%" PRIx64,
                page_addr);
      return NULL;
    }
    GPtrArray* events = g_ptr_array_new_with_free_func(g_free);
    g_ptr_array_add(events, event);
    return events;
  }

  log_info("Registered write monitoring on %zu pages of kernel .text section",
           page_count);

  return NULL;
}

static GPtrArray* create_event_kallsyms_table_write(vmi_instance_t vmi) {
  if (!vmi) {
    log_error("Invalid VMI instance at event registration.");
    return NULL;
  }
  addr_t kallsyms_offset_addr = 0;
  if ((vmi_translate_ksym2v(vmi, "kallsyms_offsets", &kallsyms_offset_addr) !=
       VMI_SUCCESS)) {
    log_warn("Could not resolve kallsyms_offsets symbol.");
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
      log_debug("Resolved %u kallsyms entries (total size: %zu bytes)",
                num_syms, kallsyms_size);
    } else {
      log_debug(
          "Failed to read kallsyms_num_syms, falling back to default size.");
    }
  } else {
    log_debug(
        "Could not resolve kallsyms_num_syms, falling back to default size.");
  }
  addr_t kallsyms_offset_phy_addr = 0;
  if (kallsyms_offset_addr == 0 ||
      vmi_translate_kv2p(vmi, kallsyms_offset_addr,
                         &kallsyms_offset_phy_addr) != VMI_SUCCESS ||
      !kallsyms_offset_phy_addr) {
    log_warn("Failed to translate kallsyms_offsets VA->PA");
    return NULL;
  }
  vmi_event_t* event = setup_memory_event(
      kallsyms_offset_phy_addr, VMI_MEMACCESS_W, event_kallsyms_write_callback);
  if (!event) {
    return NULL;
  }

  GPtrArray* events = g_ptr_array_new_with_free_func(g_free);
  g_ptr_array_add(events, event);
  return events;
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

    GPtrArray* events = entry->create_func(event_handler->vmi);
    if (!events || events->len == 0) {
      if (events)
        g_ptr_array_free(events, TRUE);
      log_warn("Failed to create events for: %s", entry->description);
      continue;
    }

    event_handler_register_event_task(event_handler, entry->task_id, events);

    registered_count++;
    log_info("Successfully registered: %s (%u sub-events)", entry->description,
             events->len);
  }

  log_info("Registered %d out of %zu event tasks", registered_count,
           event_task_map_size);
  return registered_count;
}

int register_event_task_by_id(event_handler_t* event_handler,
                              event_task_id_t task_id) {
  // Preconditions
  if (!event_handler) {
    log_error("Event handler is NULL");
    return -1;
  }

  if (task_id >= EVENT_TASK_ID_MAX || task_id < 0) {
    log_error("Invalid event task ID: %d", task_id);
    return -1;
  }
  const event_task_map_entry_t* entry = &event_task_map[task_id];

  if (entry->task_id == task_id) {
    log_info("Registering specific event task: %s", entry->description);

    GPtrArray* events = entry->create_func(event_handler->vmi);
    if (events) {
      event_handler_register_event_task(event_handler, entry->task_id, events);
      log_info("Successfully registered: %s", entry->description);
      return 1;
    }

    log_error("Failed to create event for: %s", entry->description);
    return -1;
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
