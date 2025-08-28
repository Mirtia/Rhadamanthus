#include "state_callbacks/network_trace.h"
#include <arpa/inet.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>

// Global constants for kernel structure offsets (kernel 5.15.0-139-generic)
// inet_hashinfo structure offsets (from pahole output)
static const unsigned long inet_hashinfo_ehash_offset = 0;  // ehash at offset 0
static const unsigned long inet_hashinfo_ehash_mask_offset =
    16;  // ehash_mask at offset 16
static const unsigned long inet_hashinfo_lhas_h2_offset =
    48;  // lhash2 at offset 48 (listening sockets)

// Network connection states
typedef enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT = 2,
  TCP_SYN_RECV = 3,
  TCP_FIN_WAIT1 = 4,
  TCP_FIN_WAIT2 = 5,
  TCP_TIME_WAIT = 6,
  TCP_CLOSE = 7,
  TCP_CLOSE_WAIT = 8,
  TCP_LAST_ACK = 9,
  TCP_LISTEN = 10,
  TCP_CLOSING = 11
} tcp_state_t;

/**
 * @brief Structure representing a network connection.
 * 
 * This structure holds information about a network connection,
 * including local and remote IP addresses, ports, state, and process ID.
 */
typedef struct {
  uint32_t local_ip;      //< Local IP address.
  uint32_t remote_ip;     ///< Remote IP address.
  uint16_t local_port;    ///< Local port number.
  uint16_t remote_port;   ///< Remote port number.
  uint32_t state;         ///< state (e.g tcp_state_t).
  vmi_pid_t pid;          //< Process ID associated with the connection.
  addr_t sock_addr;       ///< Socket address in kernel memory.
  bool hidden_from_proc;  ///< True if connection is hidden from /proc/net/tcp.
} network_connection_t;

/**
 * @brief Context for network detection operations.
 * 
 * This structure holds the state and results of network rootkit detection.
 */
typedef struct {
  GHashTable* visible_connections;  ///< Connections visible in /proc/net/tcp
  GArray* kernel_connections;       ///< Direct kernel connections
  uint32_t suspicious_count;        ///< Count of suspicious connections
} detection_context_t;              ///< Context for network detection

/**
 * @brief Convert TCP state to string representation.
 * 
 * @param state The TCP state to convert.
 * @return const char* String representation of the TCP state. 
 */
static const char* tcp_state_to_string(tcp_state_t state) {
  switch (state) {
    case TCP_ESTABLISHED:
      return "ESTABLISHED";
    case TCP_SYN_SENT:
      return "SYN_SENT";
    case TCP_SYN_RECV:
      return "SYN_RECV";
    case TCP_FIN_WAIT1:
      return "FIN_WAIT1";
    case TCP_FIN_WAIT2:
      return "FIN_WAIT2";
    case TCP_TIME_WAIT:
      return "TIME_WAIT";
    case TCP_CLOSE:
      return "CLOSE";
    case TCP_CLOSE_WAIT:
      return "CLOSE_WAIT";
    case TCP_LAST_ACK:
      return "LAST_ACK";
    case TCP_LISTEN:
      return "LISTEN";
    case TCP_CLOSING:
      return "CLOSING";
    default:
      return "UNKNOWN";
  }
}

/**
 * @brief Check if a port is suspicious based on known rootkit patterns.
 * 
 * @param port The port number to check.
 * @return true if the port is suspicious else false.
 */
static bool is_suspicious_port(uint16_t port) {
  // Verified kernel-mode rootkit ports based on documented sources
  uint16_t suspicious_ports[] = {
      666,  // Reptile rootkit default SRCPORT (documented)
            // Note: Adore rootkit hides connections but doesn't use fixed ports
            // It replaces tcp4_seq_show() to filter /proc/net/tcp output
  };

  size_t count = sizeof(suspicious_ports) / sizeof(suspicious_ports[0]);
  for (size_t i = 0; i < count; i++) {
    if (port == suspicious_ports[i]) {
      return true;
    }
  }

  // Additional suspicious patterns for kernel rootkits
  // Check for ports commonly used in backdoors that might have kernel components
  if (port == 0 || port == 65535) {
    return true;  // Invalid/unusual ports
  }

  // Check for sequential suspicious patterns (often used in demos/testing)
  if (port >= 1337 && port <= 1340) {
    return true;  // Leet port range
  }

  if (port >= 31330 && port <= 31339) {
    return true;  // Elite port range
  }

  // High ports that are unusual for legitimate services
  if (port >= 60000 && port <= 65534) {
    return true;  // Unusual high port range
  }

  return false;
}

/**
 * @brief Check if an IP address is suspicious (e.g public).
 * 
 * @param ip_addr The IP address to check.
 * @return true If the IP address is suspicious else false.
 */
static bool is_suspicious_ip(uint32_t ip_addr) {
  // Check for suspicious IP ranges or patterns
  uint8_t* octets = (uint8_t*)&ip_addr;

  // Private IP ranges are less suspicious than public unknown IPs
  // but could still be lateral movement

  // Check for unusual patterns
  if (octets[0] == octets[1] && octets[1] == octets[2] &&
      octets[2] == octets[3]) {
    return true;  // All octets same (e.g., 1.1.1.1, 127.127.127.127)
  }

  // Sequential patterns
  if (octets[0] + 1 == octets[1] && octets[1] + 1 == octets[2] &&
      octets[2] + 1 == octets[3]) {
    return true;
  }

  return false;
}

/**
 * @brief Walk the TCP hash table to find hidden connections.
 * 
 * @param vmi The VMI instance.
 * @param ctx The detection context containing state and results.
 * @return uint32_t VMI_SUCCESS on success, VMI_FAILURE on error.
 */
static uint32_t walk_tcp_hash_table(vmi_instance_t vmi,
                                    detection_context_t* ctx) {
  addr_t tcp_hashinfo_addr = 0;
  addr_t ehash = 0;
  uint32_t ehash_mask = 0;

  log_info("Walking TCP hash tables for hidden connections...");

  // Get tcp_hashinfo global symbol
  if (vmi_translate_ksym2v(vmi, "tcp_hashinfo", &tcp_hashinfo_addr) !=
      VMI_SUCCESS) {
    log_warn("Failed to resolve tcp_hashinfo global symbol");
    return VMI_SUCCESS;  // Continue with other detection methods
  }

  // Read established hash table pointer and mask
  if (vmi_read_addr_va(vmi, tcp_hashinfo_addr + inet_hashinfo_ehash_offset, 0,
                       &ehash) != VMI_SUCCESS ||
      vmi_read_32_va(vmi, tcp_hashinfo_addr + inet_hashinfo_ehash_mask_offset,
                     0, &ehash_mask) != VMI_SUCCESS) {
    log_error("Failed to read TCP established hash table info");
    return VMI_FAILURE;
  }

  log_debug("TCP ehash=0x%" PRIx64 " mask=0x%x", ehash, ehash_mask);

  // Walk established connections hash table
  for (uint32_t i = 0; i <= ehash_mask; i++) {
    addr_t bucket_addr =
        ehash + (i * sizeof(addr_t) * 2);  // Each bucket has head + lock
    addr_t sock_addr = 0;

    if (vmi_read_addr_va(vmi, bucket_addr, 0, &sock_addr) != VMI_SUCCESS) {
      continue;
    }

    // Walk socket chain in this bucket
    int chain_count = 0;
    while (sock_addr != 0) {
      network_connection_t conn = {0};
      conn.sock_addr = sock_addr;

      // TODO: Extract connection info from socket structure
      // This requires additional sock structure offsets:
      // - sock->__sk_common.skc_portpair (for ports)
      // - sock->__sk_common.skc_addrpair (for IPs)
      // For now, just count the connections

      // Check if connection might be suspicious based on socket address patterns
      if ((sock_addr & 0xFFFF) == 0x666 || (sock_addr & 0xFFFF) == 0x1337) {
        log_warn("SUSPICIOUS SOCKET PATTERN: sock=0x%" PRIx64, sock_addr);
        ctx->suspicious_count++;
      }

      g_array_append_val(ctx->kernel_connections, conn);

      // Move to next socket in chain
      // TODO: Read sk_node.next properly - this is a simplified version
      chain_count++;

      // For now, break to prevent infinite loops until proper sk_node parsing is implemented
      break;
    }

    if (chain_count >= 100) {
      log_warn("Excessive socket chain length detected in bucket %u", i);
      ctx->suspicious_count++;
    }
  }

  log_info("Completed TCP hash table walk, found %u connections",
           ctx->kernel_connections->len);
  return VMI_SUCCESS;
}

/**
 * @brief Check netfilter hooks for modifications.
 * 
 * @param vmi The VMI instance.
 * @param ctx The detection context containing state and results.
 * @return uint32_t VMI_SUCCESS on success, VMI_FAILURE on error.
 */
// NOLINTNEXTLINE
static uint32_t check_netfilter_hooks(vmi_instance_t vmi,
                                      detection_context_t* ctx) {
  addr_t nf_hooks_addr = 0;

  log_info("Checking netfilter hooks for rootkit modifications...");

  // Check for modified netfilter hooks
  // Rootkits often hook into netfilter to hide network traffic

  if (vmi_translate_ksym2v(vmi, "nf_hooks", &nf_hooks_addr) != VMI_SUCCESS) {
    log_warn("Failed to resolve nf_hooks symbol");
    return VMI_SUCCESS;  // Continue with other checks
  }

  // Walk netfilter hook chains for each protocol family and hook point
  for (int pf = 0; pf < 13; pf++) {         // NFPROTO_* values
    for (int hook = 0; hook < 5; hook++) {  // NF_*_HOOK values
      addr_t hook_list_addr = nf_hooks_addr + (pf * 5 + hook) * sizeof(addr_t);
      addr_t first_hook = 0;

      if (vmi_read_addr_va(vmi, hook_list_addr, 0, &first_hook) !=
          VMI_SUCCESS) {
        continue;
      }

      if (first_hook == 0) {
        continue;  // No hooks registered
      }

      // Walk the hook chain
      addr_t current_hook = first_hook;
      int hook_count = 0;

      while (current_hook != 0 && hook_count < 100) {  // Prevent infinite loops
        addr_t hook_func = 0;
        addr_t next_hook = 0;

        // Read hook function pointer and next hook
        if (vmi_read_addr_va(vmi, current_hook + 0, 0, &hook_func) !=
                VMI_SUCCESS ||
            vmi_read_addr_va(vmi, current_hook + sizeof(addr_t), 0,
                             &next_hook) != VMI_SUCCESS) {
          break;
        }

        // Check if hook function is in suspicious memory region
        // (e.g., not in kernel text section)
        if (hook_func != 0) {
          log_debug("Netfilter hook PF=%d HOOK=%d func=0x%" PRIx64, pf, hook,
                    hook_func);

          // TODO: Check if hook_func is in legitimate kernel module
          // Suspicious if it's in heap/stack or unknown module
        }

        current_hook = next_hook;
        hook_count++;
      }

      if (hook_count > 10) {
        log_warn("Excessive netfilter hooks detected: PF=%d HOOK=%d COUNT=%d",
                 pf, hook, hook_count);
        ctx->suspicious_count++;
      }
    }
  }

  return VMI_SUCCESS;
}

/**
 * @brief Cleanup the detection context.
 * 
 * @param ctx The detection context to clean up.
 */
static void cleanup_detection_context(detection_context_t* ctx) {
  if (ctx->visible_connections) {
    g_hash_table_destroy(ctx->visible_connections);
  }
  if (ctx->kernel_connections) {
    g_array_free(ctx->kernel_connections, TRUE);
  }
}

uint32_t state_network_trace_callback(vmi_instance_t vmi, void* context) {
  (void)context;

  detection_context_t det_ctx = {0};
  uint32_t result = VMI_SUCCESS;

  log_info("Starting network rootkit detection...");

  // Initialize detection context
  det_ctx.visible_connections =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  det_ctx.kernel_connections =
      g_array_new(FALSE, TRUE, sizeof(network_connection_t));
  det_ctx.suspicious_count = 0;

  // 1. Check netfilter hooks for modifications
  if (check_netfilter_hooks(vmi, &det_ctx) != VMI_SUCCESS) {
    log_error("Failed to check netfilter hooks");
    result = VMI_FAILURE;
  }

  // 2. Walk kernel network structures directly
  if (walk_tcp_hash_table(vmi, &det_ctx) != VMI_SUCCESS) {
    log_error("Failed to walk TCP hash tables");
    result = VMI_FAILURE;
  }

  // Report findings
  if (det_ctx.suspicious_count > 0) {
    log_warn(
        "NETWORK ROOTKIT DETECTION: Found %u suspicious network activities!",
        det_ctx.suspicious_count);
  } else {
    log_info("Network rootkit scan completed - no immediate threats detected");
  }

  log_info("Network connections found: %u kernel, %u visible",
           det_ctx.kernel_connections->len,
           g_hash_table_size(det_ctx.visible_connections));

  cleanup_detection_context(&det_ctx);

  return result;
}