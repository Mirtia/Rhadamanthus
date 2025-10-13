#include "event_callbacks/network_monitor.h"
#include <arpa/inet.h>
#include <glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include <time.h>
#include "event_callbacks/responses/network_monitor_response.h"
#include "event_handler.h"
#include "json_serializer.h"
#include "offsets.h"
#include "utils.h"

/**
 * @brief Log network function call details and security context
 * 
 * Extracts and logs network operation details from kernel function arguments.
 * Useful for detecting rootkit network activity, backdoors, and unauthorized modifications.
 * 
 * @param vmi VMI instance
 * @param func_name Network function name
 * @param arg1 First argument (RDI)
 * @param arg2 Second argument (RSI)
 * @param arg3 Third argument (RDX)
 * @param kaddr Kernel address where breakpoint was hit
 */
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static void log_network_function_info(vmi_instance_t vmi, const char* func_name,
                                      uint64_t arg1, uint64_t arg2,
                                      uint64_t arg3, uint64_t kaddr) {
  if (!func_name) {
    log_debug("INTERRUPT_NETWORK_MONITOR: Unknown function @0x%" PRIx64, kaddr);
    return;
  }

  if (strstr(func_name, "inet_bind")) {
    log_info("NET: inet_bind()");
    if (arg2 != 0 && arg3 >= 8) {
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, arg2, 0, &family) == VMI_SUCCESS &&
          family == AF_INET) {
        uint16_t port = 0;
        uint32_t ip_addr = 0;
        if (vmi_read_16_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_PORT_OFFSET, 0,
                           &port) == VMI_SUCCESS &&
            vmi_read_32_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_ADDR_OFFSET, 0,
                           &ip_addr) == VMI_SUCCESS) {
          struct in_addr addr = {.s_addr = ip_addr};
          uint16_t host_port = ntohs(port);
          log_info("  Bind %s:%u [%s port, %s IP]", inet_ntoa(addr), host_port,
                   get_port_classification(host_port),
                   get_ip_type_string(ip_addr));
        }
      } else if (family == AF_INET6) {
        log_info("  IPv6 bind");
      }
    }
  } else if (strstr(func_name, "inet_listen")) {
    log_info("NET: inet_listen() backlog=%" PRIu64, arg2);
  } else if (strstr(func_name, "inet_accept")) {
    log_info("NET: inet_accept()%s%s", (arg3 & 0x800) ? " [non-blocking]" : "",
             (arg3 & 0x80000) ? " [cloexec]" : "");
  } else if (strstr(func_name, "tcp_connect")) {
    log_info("NET: tcp_connect()");
    char src_info[64] = {0};
    char dst_info[64] = {0};

    if (arg1 != 0) {
      uint16_t src_port_raw = 0;
      uint32_t src_ip = 0;
      if (vmi_read_16_va(vmi, arg1 + LINUX_SKC_NUM_OFFSET, 0, &src_port_raw) ==
              VMI_SUCCESS &&
          vmi_read_32_va(vmi, arg1 + LINUX_SKC_RCV_SADDR_OFFSET, 0, &src_ip) ==
              VMI_SUCCESS) {
        struct in_addr src_addr = {.s_addr = src_ip};
        (void)snprintf(src_info, sizeof(src_info), "%s:%u", inet_ntoa(src_addr),
                       ntohs(src_port_raw));
      }
    }

    if (arg2 != 0 && arg3 >= 8) {
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, arg2, 0, &family) == VMI_SUCCESS &&
          family == AF_INET) {
        uint16_t port_raw = 0;
        uint32_t ip_addr = 0;
        if (vmi_read_16_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_PORT_OFFSET, 0,
                           &port_raw) == VMI_SUCCESS &&
            vmi_read_32_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_ADDR_OFFSET, 0,
                           &ip_addr) == VMI_SUCCESS) {
          struct in_addr dst_addr = {.s_addr = ip_addr};
          (void)snprintf(dst_info, sizeof(dst_info), "%s:%u [%s]",
                         inet_ntoa(dst_addr), ntohs(port_raw),
                         get_ip_type_string(ip_addr));
        }
      }
    }

    if (src_info[0] && dst_info[0]) {
      log_info("  %s -> %s", src_info, dst_info);
    }
  } else if (strstr(func_name, "tcp_accept")) {
    log_info("NET: tcp_accept()%s%s", (arg2 & 0x800) ? " [non-blocking]" : "",
             (arg2 & 0x80000) ? " [cloexec]" : "");
  } else if (strstr(func_name, "tcp_close")) {
    log_info("NET: tcp_close() timeout=%" PRIu64, arg2);
  } else if (strstr(func_name, "tcp_shutdown")) {
    const char* how = (arg2 == 0)   ? "RD"
                      : (arg2 == 1) ? "WR"
                      : (arg2 == 2) ? "RDWR"
                                    : "?";
    log_info("NET: tcp_shutdown() how=%s", how);
  } else if (strstr(func_name, "udp_bind")) {
    log_info("NET: udp_bind()");
    if (arg2 != 0 && arg3 >= 8) {
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, arg2, 0, &family) == VMI_SUCCESS &&
          family == AF_INET) {
        uint16_t port = 0;
        uint32_t ip_addr = 0;
        if (vmi_read_16_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_PORT_OFFSET, 0,
                           &port) == VMI_SUCCESS &&
            vmi_read_32_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_ADDR_OFFSET, 0,
                           &ip_addr) == VMI_SUCCESS) {
          struct in_addr addr = {.s_addr = ip_addr};
          log_info("  Bind %s:%u [%s]", inet_ntoa(addr), ntohs(port),
                   get_ip_type_string(ip_addr));
        }
      }
    }
  } else if (strstr(func_name, "udp_connect")) {
    log_info("NET: udp_connect()");
    if (arg2 != 0 && arg3 >= 8) {
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, arg2, 0, &family) == VMI_SUCCESS &&
          family == AF_INET) {
        uint16_t port = 0;
        uint32_t ip_addr = 0;
        if (vmi_read_16_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_PORT_OFFSET, 0,
                           &port) == VMI_SUCCESS &&
            vmi_read_32_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_ADDR_OFFSET, 0,
                           &ip_addr) == VMI_SUCCESS) {
          struct in_addr addr = {.s_addr = ip_addr};
          log_info("  Dest %s:%u [%s]", inet_ntoa(addr), ntohs(port),
                   get_ip_type_string(ip_addr));
        }
      }
    }
  } else if (strstr(func_name, "udp_disconnect")) {
    log_info("NET: udp_disconnect()");
  } else if (strstr(func_name, "nf_register_net_hook")) {
    log_info("NET: nf_register_net_hook()");
    if (arg2 != 0) {
      uint32_t hook_position = 0;
      uint8_t protocol_family = 0;
      if (vmi_read_32_va(vmi, arg2 + LINUX_NF_HOOK_OPS_HOOKNUM_OFFSET, 0,
                         &hook_position) == VMI_SUCCESS &&
          vmi_read_8_va(vmi, arg2 + LINUX_NF_HOOK_OPS_PF_OFFSET, 0,
                        &protocol_family) == VMI_SUCCESS) {
        const char* hooks[] = {"PRE_ROUTING", "LOCAL_IN", "FORWARD",
                               "LOCAL_OUT", "POST_ROUTING"};
        const char* hook_name =
            (hook_position < 5) ? hooks[hook_position] : "?";
        log_info("  Hook=%s pf=%u", hook_name, protocol_family);
      }
    }
  } else if (strstr(func_name, "nf_unregister_net_hook")) {
    log_info("NET: nf_unregister_net_hook()");
  } else if (strstr(func_name, "dev_open")) {
    log_info("NET: dev_open() device=0x%" PRIx64, arg1);
  } else if (strstr(func_name, "dev_close")) {
    log_info("NET: dev_close() device=0x%" PRIx64, arg1);
  } else {
    log_debug("INTERRUPT_NETWORK_MONITOR: %s @0x%" PRIx64 " args: 0x%" PRIx64
              " 0x%" PRIx64 " 0x%" PRIx64,
              func_name, kaddr, arg1, arg2, arg3);
  }
}

/**
 * @brief Build structured network function information
 * 
 * @param vmi VMI instance
 * @param func_name Name of the network function being called
 * @param arg1 First argument (RDI)
 * @param arg2 Second argument (RSI) 
 * @param arg3 Third argument (RDX)
 * @return Structured network function information (caller must free)
 */
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static network_function_info_t* build_network_function_info(
    vmi_instance_t vmi, const char* func_name, uint64_t arg1, uint64_t arg2,
    uint64_t arg3) {
  if (!func_name) {
    return NULL;
  }

  network_connection_info_t* connection = NULL;
  char* function_type = NULL;
  char* operation = NULL;
  uint64_t timeout = 0;
  uint64_t backlog = 0;
  uint64_t flags = 0;

  if (strstr(func_name, "tcp_connect")) {
    function_type = g_strdup("TCP_CONNECT");
    operation = g_strdup("connection establishment");

    char *src_ip = NULL, *dst_ip = NULL;
    uint16_t src_port = 0, dst_port = 0;

    if (arg1 != 0) {
      addr_t skc_addr = (addr_t)arg1;
      uint16_t src_port_raw = 0;
      if (vmi_read_16_va(vmi, skc_addr + LINUX_SKC_NUM_OFFSET, 0,
                         &src_port_raw) == VMI_SUCCESS) {
        src_port = ntohs(src_port_raw);
        uint32_t src_ip_raw = 0;
        if (vmi_read_32_va(vmi, skc_addr + LINUX_SKC_RCV_SADDR_OFFSET, 0,
                           &src_ip_raw) == VMI_SUCCESS) {
          struct in_addr src_addr = {.s_addr = src_ip_raw};
          src_ip = g_strdup(inet_ntoa(src_addr));
        }
      }
    }

    if (arg2 != 0 && arg3 >= 8) {
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, arg2, 0, &family) == VMI_SUCCESS) {
        if (family == AF_INET) {
          uint16_t port_raw = 0;
          uint32_t ip_raw = 0;
          if (vmi_read_16_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_PORT_OFFSET, 0,
                             &port_raw) == VMI_SUCCESS &&
              vmi_read_32_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_ADDR_OFFSET, 0,
                             &ip_raw) == VMI_SUCCESS) {
            dst_port = ntohs(port_raw);
            struct in_addr dst_addr = {.s_addr = ip_raw};
            dst_ip = g_strdup(inet_ntoa(dst_addr));
          }
        }
      }
    }

    connection =
        network_connection_info_new(src_ip, src_port, dst_ip, dst_port);

    g_free(src_ip);
    g_free(dst_ip);
  } else if (strstr(func_name, "nf_register_net_hook")) {
    function_type = g_strdup("NETFILTER_REGISTER");
    operation = g_strdup("Register packet filter hook");

    if (arg1 != 0) {
      uint32_t hook_position = 0;
      uint32_t protocol_family = 0;
      if (vmi_read_32_va(vmi, arg1 + LINUX_NF_HOOK_OPS_HOOKNUM_OFFSET, 0,
                         &hook_position) == VMI_SUCCESS &&
          vmi_read_32_va(vmi, arg1 + LINUX_NF_HOOK_OPS_PF_OFFSET, 0,
                         &protocol_family) == VMI_SUCCESS) {
        flags = hook_position;
        timeout = protocol_family;
      }
    }
  } else if (strstr(func_name, "nf_unregister_net_hook")) {
    function_type = g_strdup("NETFILTER_UNREGISTER");
    operation = g_strdup("Unregister packet filter hook");

    if (arg1 != 0) {
      uint32_t hook_position = 0;
      uint32_t protocol_family = 0;
      if (vmi_read_32_va(vmi, arg1 + LINUX_NF_HOOK_OPS_HOOKNUM_OFFSET, 0,
                         &hook_position) == VMI_SUCCESS &&
          vmi_read_32_va(vmi, arg1 + LINUX_NF_HOOK_OPS_PF_OFFSET, 0,
                         &protocol_family) == VMI_SUCCESS) {
        flags = hook_position;
        timeout = protocol_family;
      }
    }
  } else if (strstr(func_name, "tcp_close")) {
    function_type = g_strdup("TCP_CLOSE");
    operation = g_strdup("connection closure");

    if (arg1 != 0) {
      addr_t skc_addr = (addr_t)arg1;
      uint16_t src_port_raw = 0, dst_port_raw = 0;
      uint32_t src_ip_raw = 0, dst_ip_raw = 0;

      if (vmi_read_16_va(vmi, skc_addr + LINUX_SKC_NUM_OFFSET, 0,
                         &src_port_raw) == VMI_SUCCESS &&
          vmi_read_16_va(vmi, skc_addr + LINUX_SKC_DPORT_OFFSET, 0,
                         &dst_port_raw) == VMI_SUCCESS &&
          vmi_read_32_va(vmi, skc_addr + LINUX_SKC_RCV_SADDR_OFFSET, 0,
                         &src_ip_raw) == VMI_SUCCESS &&
          vmi_read_32_va(vmi, skc_addr + LINUX_SKC_DADDR_OFFSET, 0,
                         &dst_ip_raw) == VMI_SUCCESS) {

        uint16_t src_port = ntohs(src_port_raw);
        uint16_t dst_port = ntohs(dst_port_raw);

        struct in_addr src_addr = {.s_addr = src_ip_raw};
        struct in_addr dst_addr = {.s_addr = dst_ip_raw};
        char* src_ip = g_strdup(inet_ntoa(src_addr));
        char* dst_ip = g_strdup(inet_ntoa(dst_addr));

        connection =
            network_connection_info_new(src_ip, src_port, dst_ip, dst_port);

        g_free(src_ip);
        g_free(dst_ip);
      }
    }
  } else {
    function_type = g_strdup("UNKNOWN");
    operation = g_strdup("unknown network operation");
  }

  network_function_info_t* info =
      network_function_info_new(function_type, operation, connection, NULL,
                                timeout, backlog, flags, NULL);

  g_free(function_type);
  g_free(operation);

  return info;
}

static event_response_t event_network_monitor_ss_callback(vmi_instance_t vmi,
                                                          vmi_event_t* event) {

  nf_bp_ctx_t* ctx = (nf_bp_ctx_t*)event->data;
  if (!ctx) {
    log_error("INTERRUPT_NETWORK_MONITOR: NULL context in SS handler.");
    return VMI_EVENT_INVALID;
  }

  // INT3 instruction opcode for breakpoints
  uint8_t int3 = 0xCC;
  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &int3) != VMI_SUCCESS) {
    log_warn("Failed to re-arm breakpoint at 0x%" PRIx64, ctx->kaddr);
  } else {
    log_debug("Breakpoint re-armed at 0x%" PRIx64 " on vCPU %u", ctx->kaddr,
              event->vcpu_id);
  }

  if (vmi_toggle_single_step_vcpu(vmi, event, event->vcpu_id, false) !=
      VMI_SUCCESS) {
    log_warn("Failed to disable single-step");
  }

  // Unregister the single-step event to prevent memory leaks
  if (vmi_clear_event(vmi, &ctx->ss_evt, NULL) != VMI_SUCCESS) {
    log_warn("INTERRUPT_NETWORK_MONITOR: Failed to clear single-step event");
  }

  log_debug("INTERRUPT_NETWORK_MONITOR: Breakpoint re-armed on vCPU %u",
            event->vcpu_id);

  log_vcpu_state(vmi, event->vcpu_id, ctx->kaddr, "SS exit");
  return VMI_EVENT_RESPONSE_NONE;
}

event_response_t event_network_monitor_callback(vmi_instance_t vmi,
                                                vmi_event_t* event) {
  if (!vmi || !event) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, INVALID_ARGUMENTS,
        "Invalid arguments to netfilter hook write callback.");
  }

  nf_bp_ctx_t* ctx = (nf_bp_ctx_t*)event->data;
  if (!ctx) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, INVALID_ARGUMENTS,
        "NULL context in INT3 handler.");
  }

  if (ctx->kaddr == 0) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, INVALID_ARGUMENTS,
        "Invalid kaddr in context.");
  }

  uint32_t vcpu_id = event->vcpu_id;
  uint64_t rip = 0, cr3 = 0, rsp = 0;
  if (get_standard_registers(vmi, vcpu_id, &rip, &cr3, &rsp) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to get standard registers.");
  }

  event->interrupt_event.reinject = 0;
  event->interrupt_event.insn_length = 0;

  // Get additional register values for comprehensive logging
  reg_t rdi = 0, rsi = 0, rdx = 0, rcx = 0, r8 = 0, r9 = 0;
  if (vmi_get_vcpureg(vmi, &rdi, RDI, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to get RDI register value.");
  }
  if (vmi_get_vcpureg(vmi, &rsi, RSI, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to get RSI register value.");
  }
  if (vmi_get_vcpureg(vmi, &rdx, RDX, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to get RDX register value.");
  }
  if (vmi_get_vcpureg(vmi, &rcx, RCX, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to get RCX register value.");
  }
  if (vmi_get_vcpureg(vmi, &r8, R8, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to get R8 register value.");
  }
  if (vmi_get_vcpureg(vmi, &r9, R9, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to get R9 register value.");
  }

  const char* func_name = ctx->symname ? ctx->symname : "unknown";

  log_network_function_info(vmi, func_name, (uint64_t)rdi, (uint64_t)rsi,
                            (uint64_t)rdx, ctx->kaddr);

  network_function_info_t* network_info = build_network_function_info(
      vmi, func_name, (uint64_t)rdi, (uint64_t)rsi, (uint64_t)rdx);

  network_monitor_data_t* nf_data = network_monitor_data_new(
      vcpu_id, rip, rsp, cr3, ctx->kaddr, (uint64_t)rdi, (uint64_t)rsi,
      (uint64_t)rdx, ctx->symname, network_info);
  if (!nf_data) {
    if (network_info) {
      network_function_info_free(network_info);
    }
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, MEMORY_ALLOCATION_FAILURE,
        "Failed to allocate memory for network monitor data.");
  }

  if (vmi_write_8_va(vmi, ctx->kaddr, 0, &ctx->orig) != VMI_SUCCESS) {
    network_monitor_data_free(nf_data);
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to restore original byte.");
  }

  memset(&ctx->ss_evt, 0, sizeof(ctx->ss_evt));
  ctx->ss_evt.version = VMI_EVENTS_VERSION;
  ctx->ss_evt.type = VMI_EVENT_SINGLESTEP;
  ctx->ss_evt.callback = event_network_monitor_ss_callback;
  ctx->ss_evt.data = ctx;
  ctx->ss_evt.ss_event.enable = 1;

  if (vmi_register_event(vmi, &ctx->ss_evt) != VMI_SUCCESS) {
    log_warn(
        "INTERRUPT_NETWORK_MONITOR: Failed to register SINGLESTEP event. "
        "Breakpoint will not be re-armed");
    return log_success_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, (void*)nf_data,
        (void (*)(void*))network_monitor_data_free);
  }

  if (vmi_toggle_single_step_vcpu(vmi, &ctx->ss_evt, vcpu_id, true) !=
      VMI_SUCCESS) {
    log_warn(
        "INTERRUPT_NETWORK_MONITOR: Failed to enable single-step on vCPU "
        "%u. "
        "Breakpoint will not be re-armed",
        vcpu_id);
  }

  log_debug("INTERRUPT_NETWORK_MONITOR: Single-step enabled on vCPU %u",
            vcpu_id);

  log_vcpu_state(vmi, vcpu_id, ctx->kaddr, "CB exit");

  return log_success_and_queue_response_interrupt(
      "network_monitor", INTERRUPT_NETWORK_MONITOR, (void*)nf_data,
      (void (*)(void*))network_monitor_data_free);
}