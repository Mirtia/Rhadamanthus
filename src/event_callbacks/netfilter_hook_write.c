#include "event_callbacks/netfilter_hook_write.h"
#include <log.h>

#include "event_callbacks/netfilter_hook_write.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "offsets.h"
#include "utils.h"

/**
 * @brief Structure to hold hook modification details
 */
typedef struct {
  addr_t hook_entry_addr;     ///< Address of the hook entry being modified
  addr_t old_hook_func;       ///< Previous hook function address
  addr_t new_hook_func;       ///< New hook function address
  addr_t hook_priv;           ///< Hook private data
  uint32_t hook_family;       ///< Hook family (IPv4, IPv6, ARP, Bridge)
  uint32_t hook_type;         ///< Hook type (PRE_ROUTING, LOCAL_IN, etc.)
  bool is_suspicious;         ///< Whether this modification is suspicious
} hook_modification_t;

/**
 * @brief Analyze hook function address for suspicious patterns
 * 
 * @param vmi VMI instance
 * @param hook_func Hook function address to analyze
 * @return true if suspicious, false otherwise
 */
static bool analyze_hook_function(vmi_instance_t vmi, addr_t hook_func) {
  if (!hook_func) {
    log_debug("Hook function is NULL");
    return false;
  }

  // Check if function is outside kernel text section (major red flag)
  if (!is_in_kernel_text(vmi, hook_func)) {
    log_warn("Hook function 0x%" PRIx64 " is outside kernel text!", hook_func);
    return true;
  }

  // Check for common rootkit hook addresses/patterns
  // Many rootkits use predictable address ranges or patterns
  
  // Check if address looks like module address (could be legitimate or malicious)
  bool in_module_area = false;
  if (hook_func >= 0xffffffffa0000000ULL && hook_func <= 0xfffffffffeffffffULL) {
    in_module_area = true;
    log_debug("Hook function 0x%" PRIx64 " appears to be in module area", hook_func);
  }

  // Additional suspicious patterns
  // 1. Functions in unusual high memory ranges
  if (hook_func > 0xffffffff00000000ULL && !in_module_area) {
    log_debug("Hook function in suspicious high memory range: 0x%" PRIx64, hook_func);
    return true;
  }

  // 2. Check for alignment - legitimate kernel functions are typically aligned
  if ((hook_func & 0xF) != 0) {
    log_debug("Hook function poorly aligned: 0x%" PRIx64, hook_func);
    return true;
  }

  // If in module area, we might want to do additional checks
  // but for now, we'll consider it potentially suspicious but not definitively
  return in_module_area;
}

/**
 * @brief Determine hook family and type from memory address
 * 
 * @param vmi VMI instance  
 * @param hook_entry_addr Address of hook entry
 * @param mod Details structure to populate
 * @return true on success, false on failure
 */
static bool identify_hook_context(vmi_instance_t vmi, addr_t hook_entry_addr, 
                                  hook_modification_t* mod) {
  addr_t init_net_addr = 0;
  
  if (vmi_translate_ksym2v(vmi, "init_net", &init_net_addr) != VMI_SUCCESS) {
    log_debug("Failed to resolve init_net for hook context");
    return false;
  }

  addr_t netns_nf_addr = init_net_addr + LINUX_NET_NF_OFFSET;

  // Define hook array information
  struct {
    const char* name;
    size_t offset;
    int count;
    uint32_t family_id;
  } hook_arrays[] = {
      {"IPv4", LINUX_NETNF_HOOKS_IPV4_OFFSET, 5, 2},      // AF_INET
      {"IPv6", LINUX_NETNF_HOOKS_IPV6_OFFSET, 5, 10},     // AF_INET6  
      {"ARP", LINUX_NETNF_HOOKS_ARP_OFFSET, 3, 3},        // AF_ARP
      {"Bridge", LINUX_NETNF_HOOKS_BRIDGE_OFFSET, 5, 7},  // AF_BRIDGE
  };

  // Try to identify which hook array and index this address belongs to
  for (size_t arr = 0; arr < sizeof(hook_arrays) / sizeof(hook_arrays[0]); arr++) {
    for (int hook = 0; hook < hook_arrays[arr].count; hook++) {
      addr_t hook_entries_addr = 0;
      addr_t slot_addr = netns_nf_addr + hook_arrays[arr].offset + hook * sizeof(addr_t);

      if (vmi_read_addr_va(vmi, slot_addr, 0, &hook_entries_addr) != VMI_SUCCESS) {
        continue;
      }
      if (!hook_entries_addr) {
        continue;
      }

      // Check if our hook_entry_addr falls within this hook array
      addr_t hooks_start = hook_entries_addr + NF_HOOK_ENTRIES_PAD;
      
      uint16_t num_hook_entries = 0;
      if (vmi_read_16_va(vmi, hook_entries_addr + NF_HOOK_ENTRIES_NUM_OFFSET, 0,
                         &num_hook_entries) != VMI_SUCCESS) {
        continue;
      }

      addr_t hooks_end = hooks_start + num_hook_entries * NF_HOOK_ENTRY_SIZE;
      
      if (hook_entry_addr >= hooks_start && hook_entry_addr < hooks_end) {
        // Found it! Calculate which entry index
        uint32_t entry_index = (hook_entry_addr - hooks_start) / NF_HOOK_ENTRY_SIZE;
        
        mod->hook_family = hook_arrays[arr].family_id;
        mod->hook_type = hook;
        
        log_debug("Hook modification in %s family, hook type %d, entry %u",
                 hook_arrays[arr].name, hook, entry_index);
        return true;
      }
    }
  }

  log_debug("Could not identify hook context for address 0x%" PRIx64, hook_entry_addr);
  return false;
}

/**
 * @brief Extract hook modification details from write event
 * 
 * @param vmi VMI instance
 * @param event VMI event containing write details
 * @param mod Structure to populate with modification details
 * @return true on success, false on failure
 */
static bool extract_hook_modification(vmi_instance_t vmi, vmi_event_t* event,
                                      hook_modification_t* mod) {
  memset(mod, 0, sizeof(*mod));
  
  // Get write target address (where the write occurred)
  mod->hook_entry_addr = event->mem_event.gla;
  
  // Read the current/new hook function value at this address
  if (vmi_read_addr_va(vmi, mod->hook_entry_addr, 0, &mod->new_hook_func) != VMI_SUCCESS) {
    log_debug("Failed to read new hook function at 0x%" PRIx64, mod->hook_entry_addr);
    return false;
  }

  // Try to read hook private data (typically at offset +8 from function pointer)
  vmi_read_addr_va(vmi, mod->hook_entry_addr + 8, 0, &mod->hook_priv);

  // For old value, we could potentially get it from the event or maintain state
  // For now, we'll focus on analyzing the new value
  mod->old_hook_func = 0; // Could be enhanced with state tracking

  // Identify the hook context
  identify_hook_context(vmi, mod->hook_entry_addr, mod);

  // Analyze if this modification is suspicious
  mod->is_suspicious = analyze_hook_function(vmi, mod->new_hook_func);

  return true;
}

/**
 * @brief Log detailed information about hook modification
 * 
 * @param mod Hook modification details
 */
static void log_hook_modification(const hook_modification_t* mod) {
  const char* family_names[] = {
    [2] = "IPv4", [3] = "ARP", [7] = "Bridge", [10] = "IPv6"
  };
  
  const char* hook_names[] = {
    "PRE_ROUTING", "LOCAL_IN", "FORWARD", "LOCAL_OUT", "POST_ROUTING"
  };

  const char* family_name = "Unknown";
  if (mod->hook_family < sizeof(family_names) / sizeof(family_names[0]) && 
      family_names[mod->hook_family]) {
    family_name = family_names[mod->hook_family];
  }

  const char* hook_name = "Unknown";
  if (mod->hook_type < sizeof(hook_names) / sizeof(hook_names[0])) {
    hook_name = hook_names[mod->hook_type];
  }

  if (mod->is_suspicious) {
    log_warn("SUSPICIOUS Netfilter Hook Modification:");
    log_warn("  Family: %s (%u)", family_name, mod->hook_family);
    log_warn("  Hook: %s (%u)", hook_name, mod->hook_type);
    log_warn("  Entry Address: 0x%" PRIx64, mod->hook_entry_addr);
    log_warn("  New Function: 0x%" PRIx64, mod->new_hook_func);
    log_warn("  Private Data: 0x%" PRIx64, mod->hook_priv);
    if (mod->old_hook_func) {
      log_warn("  Old Function: 0x%" PRIx64, mod->old_hook_func);
    }
  } else {
    log_info("Netfilter Hook Modification (likely legitimate):");
    log_info("  Family: %s, Hook: %s, Function: 0x%" PRIx64, 
             family_name, hook_name, mod->new_hook_func);
  }
}

/**
 * @brief Check if this write event is actually targeting a netfilter hook
 * 
 * @param vmi VMI instance
 * @param event VMI write event
 * @return true if this is a hook write, false otherwise
 */
static bool is_netfilter_hook_write(vmi_instance_t vmi, vmi_event_t* event) {
  addr_t write_addr = event->mem_event.gla;
  
  // Quick sanity checks
  if (!write_addr || write_addr < 0xffff000000000000ULL) {
    return false; // Not in kernel space
  }

  // Check if write size matches pointer size (hooks are typically function pointers)
  if (event->mem_event.bytes != sizeof(addr_t)) {
    return false;
  }

  // We could do more sophisticated checking here to verify this is actually
  // a netfilter hook structure, but for now we'll rely on the fact that
  // this callback should only be triggered for relevant memory regions
  
  return true;
}

event_response_t event_netfilter_hook_write_callback(vmi_instance_t vmi,
                                                     vmi_event_t* event) {
  if (!vmi || !event) {
    log_error("NETFILTER_HOOK_WRITE: Invalid VMI instance or event");
    return VMI_EVENT_RESPONSE_NONE;
  }

  // Verify this is actually a netfilter hook write
  if (!is_netfilter_hook_write(vmi, event)) {
    log_debug("NETFILTER_HOOK_WRITE: Write event not targeting netfilter hook");
    return VMI_EVENT_RESPONSE_NONE;
  }

  log_info("Netfilter hook write event detected - analyzing...");

  hook_modification_t modification;
  if (!extract_hook_modification(vmi, event, &modification)) {
    log_error("NETFILTER_HOOK_WRITE: Failed to extract hook modification details");
    return VMI_EVENT_RESPONSE_NONE;
  }

  // Log the modification details
  log_hook_modification(&modification);

  // If suspicious, we might want to take additional action
  if (modification.is_suspicious) {
    log_warn("NETFILTER_HOOK_WRITE: Potential rootkit activity detected!");
    
    // Additional analysis could be performed here:
    // - Dump memory around the hook function
    // - Check process context
    // - Cross-reference with known rootkit signatures
    // - Trigger additional security responses
    
    // For now, we'll just ensure this gets logged prominently
    log_warn("SECURITY ALERT: Suspicious netfilter hook modification at 0x%" PRIx64 
             " -> 0x%" PRIx64, modification.hook_entry_addr, modification.new_hook_func);
  }

  // Return NONE to continue normal execution, or could return other responses
  // depending on security policy (e.g., VMI_EVENT_RESPONSE_EMULATE to block)
  return VMI_EVENT_RESPONSE_NONE;
}