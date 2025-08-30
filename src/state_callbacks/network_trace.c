#include "state_callbacks/network_trace.h"
#include <arpa/inet.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "event_handler.h"
#include "offsets.h"
#include "utils.h"

/**
* @brief TCP connection states.
* TODO: Check if more states are needed (kernel dependent).
*/
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
  uint32_t local_ip;     ///< Local IP address.
  uint32_t remote_ip;    ///< Remote IP address.
  uint16_t local_port;   ///< Local port number.
  uint16_t remote_port;  ///< Remote port number.
  uint32_t state;        ///< State (e.g tcp_state_t).
  vmi_pid_t pid;         //< Process ID associated with the connection.
  addr_t sock_addr;      ///< Socket address in kernel memory.
} network_connection_t;

/**
 * @brief Context for network detection operations.
 * 
 * This structure holds the state and results of network rootkit detection.
 */
typedef struct {
  GArray* kernel_connections;  ///< Direct kernel connections.
  uint32_t suspicious_count;   ///< Count of suspicious connections.
} detection_context_t;         ///< Context for network detection.

/**
 * @brief Convert TCP state to string representation.
 * @note https://elixir.bootlin.com/linux/v6.16.3/source/include/net/tcp_states.h#L13
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
  uint16_t suspicious_ports[] = {
      666,  // Reptile rootkit default SRCPORT (documented)
      // Reptile has been removed from public repositories but references exist:
      // https://web.archive.org/web/20250506040024/https://github.com/f0rb1dd3n/Reptile
      665, 667,  ///< Possible Reptile variations
      4444, 5555, 6666, 7777, 8888,
      9999,  ///< Sequential and simple patterns used by malware tools and backdoors.
      1234, 2222, 3333,
      31337,  ///< Back Orifice backdoor default port (LEET).
      0,      ///< Port 0 is invalid.
      65535   ///< Highest port, invalid.
  };

  size_t count = sizeof(suspicious_ports) / sizeof(suspicious_ports[0]);
  for (size_t i = 0; i < count; i++) {
    if (port == suspicious_ports[i]) {
      log_debug("Suspicious port detected: %u", port);
      return true;
    }
  }

  // High ports that are unusual for legitimate services.
  if (port >= 60000 && port <= 65534) {
    log_debug("High range suspicious port detected: %u", port);
    return true;
  }

  return false;
}

static inline bool ipv4_is_public(uint32_t ip_be) {
  uint32_t ip_addr = ntohl(ip_be);  // compare in host byte order

// Helper: test if ip is inside CIDR (base/maskbits in host order)
#define IN(ip_addr_, base_, maskbits_)                              \
  (((ip_addr_) &                                                    \
    ((maskbits_) == 0 ? 0u : 0xFFFFFFFFu << (32 - (maskbits_)))) == \
   ((base_) & ((maskbits_) == 0 ? 0u : 0xFFFFFFFFu << (32 - (maskbits_)))))

  // ---- Non-public ranges per IANA Special-Purpose Address Registry & RFCs ----
  // IANA IPv4 Special-Purpose Address Registry (authoritative index):
  // https://www.iana.org/assignments/iana-ipv4-special-registry  (covers many items below)
  // RFC 6890 (Special-Purpose IP Address Registries): https://datatracker.ietf.org/doc/html/rfc6890

  // 0.0.0.0/8 — “this network” & 0.0.0.0/32 unspecified
  // IANA special-use overview (see registry above).
  if (IN(ip_addr, 0x00000000U, 8))
    return false;

  // 10.0.0.0/8 — Private-use (RFC 1918)
  // https://datatracker.ietf.org/doc/html/rfc1918
  if (IN(ip_addr, 0x0A000000U, 8))
    return false;

  // 100.64.0.0/10 — Shared Address Space for CGNAT (RFC 6598)
  // https://datatracker.ietf.org/doc/html/rfc6598
  if (IN(ip_addr, 0x64400000U, 10))
    return false;

  // 127.0.0.0/8 — Loopback (RFC 1122 §3.2.1.3; listed in IANA special registry)
  // RFC 1122: https://www.rfc-editor.org/rfc/rfc1122
  // IANA (explicit row for 127/8): https://www.iana.org/assignments/iana-ipv4-special-registry
  if (IN(ip_addr, 0x7F000000U, 8))
    return false;

  // 169.254.0.0/16 — Link-Local (RFC 3927)
  // https://datatracker.ietf.org/doc/html/rfc3927
  if (IN(ip_addr, 0xA9FE0000U, 16))
    return false;

  // 172.16.0.0/12 — Private-use (RFC 1918)
  // https://datatracker.ietf.org/doc/html/rfc1918
  if (IN(ip_addr, 0xAC100000U, 12))
    return false;

  // 192.0.0.0/24 — IETF Protocol Assignments (RFC 6890 §2.1; obsoletes RFC 5736)
  // RFC 6890: https://datatracker.ietf.org/doc/html/rfc6890
  // IANA registry row for 192.0.0.0/24: https://www.iana.org/assignments/iana-ipv4-special-registry
  if (IN(ip_addr, 0xC0000000U, 24))
    return false;

  // 192.0.2.0/24 — Documentation TEST-NET-1 (RFC 5737)
  // https://datatracker.ietf.org/doc/html/rfc5737
  if (IN(ip_addr, 0xC0000200U, 24))
    return false;

  // 192.88.99.0/24 — 6to4 Relay Anycast (deprecated; treat as non-public) (RFC 7526)
  // https://www.rfc-editor.org/rfc/rfc7526.html
  if (IN(ip_addr, 0xC0586300U, 24))
    return false;

  // 192.168.0.0/16 — Private-use (RFC 1918)
  // https://datatracker.ietf.org/doc/html/rfc1918
  if (IN(ip_addr, 0xC0A80000U, 16))
    return false;

  // 198.18.0.0/15 — Benchmarking (RFC 2544; recorded in IANA special registry)
  // RFC 2544: https://www.rfc-editor.org/rfc/rfc2544.html
  if (IN(ip_addr, 0xC6120000U, 15))
    return false;

  // 198.51.100.0/24 — Documentation TEST-NET-2 (RFC 5737)
  // https://datatracker.ietf.org/doc/html/rfc5737
  if (IN(ip_addr, 0xC6336400U, 24))
    return false;

  // 203.0.113.0/24 — Documentation TEST-NET-3 (RFC 5737)
  // https://datatracker.ietf.org/doc/html/rfc5737
  if (IN(ip_addr, 0xCB007100U, 24))
    return false;

  // 224.0.0.0/4 — Multicast (RFC 5771; IANA multicast registry)
  // RFC 5771: https://datatracker.ietf.org/doc/html/rfc5771
  // IANA multicast registry: https://www.iana.org/assignments/multicast-addresses
  if (IN(ip_addr, 0xE0000000U, 4))
    return false;

  // 240.0.0.0/4 — Reserved for future use; includes 255.255.255.255/32 broadcast
  // IANA special-use registry + long-standing “Class E / Future Use” designation.
  // https://www.iana.org/assignments/iana-ipv4-special-registry
  if (IN(ip_addr, 0xF0000000U, 4))
    return false;

  // If it is not in any special/non-public block, treat as public.
  return true;

#undef IN
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

  if (ipv4_is_public(ip_addr)) {
    log_debug("Public IP detected: %u.%u.%u.%u", octets[0], octets[1],
              octets[2], octets[3]);
    return true;
  }
  // Private IP ranges are less suspicious than public unknown IPs
  // but could still be lateral movement.

  // Check for unusual patterns
  // e.g. All octets same (e.g., 1.1.1.1, 127.127.127.127)
  if (octets[0] == octets[1] && octets[1] == octets[2] &&
      octets[2] == octets[3]) {
    return true;
  }

  // Sequential patterns
  // e.g. 1.2.3.4
  if (octets[0] + 1 == octets[1] && octets[1] + 1 == octets[2] &&
      octets[2] + 1 == octets[3]) {
    return true;
  }

  return false;
}

/**
 * @brief Walk the TCP hash table to find hidden connections (improved version).
 * 
 * This version actually extracts connection details from socket structures
 * instead of just counting connections.
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

  // Get tcp_hashinfo global symbol
  if (vmi_translate_ksym2v(vmi, "tcp_hashinfo", &tcp_hashinfo_addr) !=
      VMI_SUCCESS) {
    log_debug("Failed to resolve tcp_hashinfo global symbol");
    return VMI_FAILURE;
  }

  // Read established hash table pointer and mask
  if (vmi_read_addr_va(vmi,
                       tcp_hashinfo_addr + LINUX_INET_HASHINFO_EHASH_OFFSET, 0,
                       &ehash) != VMI_SUCCESS ||
      vmi_read_32_va(vmi,
                     tcp_hashinfo_addr + LINUX_INET_HASHINFO_EHASH_MASK_OFFSET,
                     0, &ehash_mask) != VMI_SUCCESS) {
    log_debug("Failed to read TCP established hash table info");
    return VMI_FAILURE;
  }

  log_debug("TCP ehash=0x%" PRIx64 " mask=0x%x", ehash, ehash_mask);

  // Walk established connections hash table
  for (uint32_t i = 0; i <= ehash_mask; i++) {
    addr_t bucket_addr =
        ehash + (i * 16);  // Each inet_ehash_bucket is ~16 bytes
    addr_t sock_addr = 0;

    // Read first socket in bucket
    if (vmi_read_addr_va(vmi, bucket_addr, 0, &sock_addr) != VMI_SUCCESS) {
      continue;
    }

    // Walk socket chain in this bucket
    int chain_count = 0;
    while (sock_addr != 0 && chain_count < 1000) {  // Prevent infinite loops
      network_connection_t conn = {0};
      conn.sock_addr = sock_addr;

      // Extract connection information from socket structure
      uint32_t daddr = 0, saddr = 0;
      uint16_t dport = 0, sport = 0;
      uint8_t state = 0;

      addr_t sock_common_addr = sock_addr + LINUX_SOCK_COMMON_OFFSET;

      // Read IP addresses and ports
      if (vmi_read_32_va(vmi, sock_common_addr + LINUX_SKC_DADDR_OFFSET, 0,
                         &daddr) == VMI_SUCCESS &&
          vmi_read_32_va(vmi, sock_common_addr + LINUX_SKC_RCV_SADDR_OFFSET, 0,
                         &saddr) == VMI_SUCCESS &&
          vmi_read_16_va(vmi, sock_common_addr + LINUX_SKC_DPORT_OFFSET, 0,
                         &dport) == VMI_SUCCESS &&
          vmi_read_16_va(vmi, sock_common_addr + LINUX_SKC_NUM_OFFSET, 0,
                         &sport) == VMI_SUCCESS &&
          vmi_read_8_va(vmi, sock_common_addr + LINUX_SKC_STATE_OFFSET, 0,
                        &state) == VMI_SUCCESS) {

        // Convert network byte order to host byte order
        conn.remote_ip = ntohl(daddr);
        conn.local_ip = ntohl(saddr);
        conn.remote_port = ntohs(dport);
        conn.local_port = sport;  // skc_num is already in host order
        conn.state = state;

        // Log the connection for debugging
        struct in_addr local_addr = {.s_addr = htonl(conn.local_ip)};
        struct in_addr remote_addr = {.s_addr = htonl(conn.remote_ip)};

        log_debug("TCP connection: %s:%u -> %s:%u state=%s",
                  inet_ntoa(local_addr), conn.local_port,
                  inet_ntoa(remote_addr), conn.remote_port,
                  tcp_state_to_string(conn.state));

        // Check for suspicious patterns
        bool is_suspicious = false;

        if (is_suspicious_port(conn.local_port) ||
            is_suspicious_port(conn.remote_port)) {
          log_warn("Suspicious Port: %s:%u -> %s:%u", inet_ntoa(local_addr),
                   conn.local_port, inet_ntoa(remote_addr), conn.remote_port);
          is_suspicious = true;
        }

        if (is_suspicious_ip(conn.local_ip) ||
            is_suspicious_ip(conn.remote_ip)) {
          log_debug("Suspicious IP: %s:%u -> %s:%u", inet_ntoa(local_addr),
                    conn.local_port, inet_ntoa(remote_addr), conn.remote_port);
          is_suspicious = true;
        }

        // Check for unusual TCP states
        if (conn.state > TCP_CLOSING) {
          log_debug("Unusual TCP state: %s:%u -> %s:%u state=%u",
                    inet_ntoa(local_addr), conn.local_port,
                    inet_ntoa(remote_addr), conn.remote_port, conn.state);
          is_suspicious = true;
        }

        if (is_suspicious) {
          ctx->suspicious_count++;
        }

        g_array_append_val(ctx->kernel_connections, conn);
      }

      // Move to next socket in chain
      addr_t next_node_addr = 0;
      if (vmi_read_addr_va(vmi,
                           sock_common_addr + LINUX_SKC_NODE_OFFSET +
                               LINUX_SKC_NODE_NEXT_OFFSET,
                           0, &next_node_addr) != VMI_SUCCESS) {
        break;
      }

      // Calculate next socket address from node address
      sock_addr = (next_node_addr != 0)
                      ? (next_node_addr - LINUX_SOCK_COMMON_OFFSET -
                         LINUX_SKC_NODE_OFFSET)
                      : 0;

      chain_count++;
    }

    // Validate?
    if (chain_count >= 100) {
      log_warn(
          "Excessive socket chain length detected in bucket %u: %d connections",
          i, chain_count);
      ctx->suspicious_count++;
    }
  }

  log_info("Completed TCP hash table walk, found %u connections",
           ctx->kernel_connections->len);

  return VMI_SUCCESS;
}

/**
 * @brief Check netfilter hooks for modifications (Kernel 5.x+ compatible).
 * 
 * In kernel 5.x+, netfilter hooks are stored per-netns in struct net
 * instead of the global nf_hooks array that existed in older kernels.
 * 
 * @param vmi The VMI instance.
 * @param ctx The detection context containing state and results.
 * @return uint32_t VMI_SUCCESS on success, VMI_FAILURE on error.
 */
static uint32_t check_netfilter_hooks(vmi_instance_t vmi,
                                      detection_context_t* ctx) {
  addr_t init_net_addr = 0;

  // Get init_net (initial network namespace) instead of old nf_hooks
  if (vmi_translate_ksym2v(vmi, "init_net", &init_net_addr) != VMI_SUCCESS) {
    log_debug("Failed to resolve init_net symbol");
    return VMI_FAILURE;
  }

  log_debug("init_net found at 0x%" PRIx64, init_net_addr);

  addr_t netns_nf_addr = init_net_addr + LINUX_NET_NF_OFFSET;
  addr_t hooks_array_addr = netns_nf_addr + LINUX_NF_HOOKS_OFFSET;

  log_debug("netns_nf at 0x%" PRIx64 ", hooks at 0x%" PRIx64, netns_nf_addr,
            hooks_array_addr);

  // Walk netfilter hook entries for each protocol family and hook point
  // hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS] = hooks[13][5]
  for (int pf = 0; pf < 13; pf++) {         // NFPROTO_* values
    for (int hook = 0; hook < 5; hook++) {  // NF_*_HOOK values

      // Calculate offset to hooks[pf][hook]
      addr_t hook_entry_ptr_addr =
          hooks_array_addr + (pf * 5 + hook) * sizeof(addr_t);

      addr_t hook_entries_addr = 0;
      if (vmi_read_addr_va(vmi, hook_entry_ptr_addr, 0, &hook_entries_addr) !=
          VMI_SUCCESS) {
        continue;
      }

      if (hook_entries_addr == 0) {
        continue;  // No hooks registered for this pf/hook combination
      }

      log_debug("Found hook entries at PF=%d HOOK=%d addr=0x%" PRIx64, pf, hook,
                hook_entries_addr);

      // Read nf_hook_entries structure
      uint16_t num_hook_entries = 0;
      if (vmi_read_16_va(vmi, hook_entries_addr, 0, &num_hook_entries) !=
          VMI_SUCCESS) {
        continue;
      }

      if (num_hook_entries == 0 || num_hook_entries > 100) {  // Sanity check
        continue;
      }

      log_debug("Found %u hook entries for PF=%d HOOK=%d", num_hook_entries, pf,
                hook);

      // Read the hooks array (starts after num_hook_entries field)
      addr_t hooks_start_addr = hook_entries_addr + sizeof(uint16_t);

      for (uint16_t i = 0; i < num_hook_entries && i < 50;
           i++) {  // Limit iterations
        addr_t hook_entry_addr =
            hooks_start_addr + i * (sizeof(addr_t) * 2);  // hook + priv
        addr_t hook_func = 0;
        addr_t hook_priv = 0;

        if (vmi_read_addr_va(vmi, hook_entry_addr, 0, &hook_func) !=
                VMI_SUCCESS ||
            vmi_read_addr_va(vmi, hook_entry_addr + sizeof(addr_t), 0,
                             &hook_priv) != VMI_SUCCESS) {
          continue;
        }

        if (hook_func == 0) {
          continue;
        }

        log_debug("Hook[%u] PF=%d HOOK=%d func=0x%" PRIx64 " priv=0x%" PRIx64,
                  i, pf, hook, hook_func, hook_priv);

        // Enhanced suspicious hook detection
        bool is_suspicious = false;

        // 1. Check if hook function is in kernel text section
        if (is_in_kernel_text(vmi, hook_func)) {
          log_debug(
              "SUSPICIOUS: Hook function in user space: PF=%d HOOK=%d "
              "func=0x%" PRIx64,
              pf, hook, hook_func);
          is_suspicious = true;
        }

        // 2. Check for common rootkit signature addresses
        // TODO: ??? There should be references here.
        uint16_t func_low_bits = hook_func & 0xFFFF;
        if (func_low_bits == 0x666 || func_low_bits == 0x1337 ||
            func_low_bits == 0xdead || func_low_bits == 0xbeef) {
          log_debug(
              "SUSPICIOUS: Hook with signature address pattern: PF=%d HOOK=%d "
              "func=0x%" PRIx64,
              pf, hook, hook_func);
          is_suspicious = true;
        }

        // 3. Check for hooks in unusual memory regions (heap, stack, etc.)
        // TODO: Hardcoded addresses is smelly code, there is no way this will work.
        if ((hook_func >= 0xffff888000000000ULL &&
             hook_func < 0xffffc87fffffffffULL)) {
          log_debug(
              "SUSPICIOUS: Hook in potential heap memory: PF=%d HOOK=%d "
              "func=0x%" PRIx64,
              pf, hook, hook_func);
          is_suspicious = true;
        }

        // 4. Check for suspicious hook private data patterns
        if (hook_priv != 0) {
          uint16_t priv_low_bits = hook_priv & 0xFFFF;
          if (priv_low_bits == 0x666 || priv_low_bits == 0x1337) {
            log_debug(
                "SUSPICIOUS: Hook private data with signature: PF=%d HOOK=%d "
                "priv=0x%" PRIx64,
                pf, hook, hook_priv);
            is_suspicious = true;
          }
        }

        // 5. Validate hook function points to executable memory
        uint32_t func_bytes = 0;
        if (vmi_read_32_va(vmi, hook_func, 0, &func_bytes) == VMI_SUCCESS) {
          uint8_t* bytes = (uint8_t*)&func_bytes;
          if (bytes[0] == 0x00 &&
              bytes[1] == 0x00) {  // All zeros - likely not code
            log_debug(
                "SUSPICIOUS: Hook function appears to contain null bytes: "
                "PF=%d HOOK=%d",
                pf, hook);
            is_suspicious = true;
          }
        }

        if (is_suspicious) {
          ctx->suspicious_count++;
        }
      }

      // Detect excessive hooks
      if (num_hook_entries > 10) {
        log_debug("Excessive netfilter hooks detected: PF=%d HOOK=%d COUNT=%u",
                  pf, hook, num_hook_entries);
        ctx->suspicious_count++;
      }

      // Detect unusual protocol families or hook points
      if (pf >= 8 || hook >= 5) {
        log_debug("Unusual netfilter parameters: PF=%d HOOK=%d", pf, hook);
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
  if (ctx->kernel_connections) {
    g_array_free(ctx->kernel_connections, TRUE);
  }
}

uint32_t state_network_trace_callback(vmi_instance_t vmi, void* context) {
  if (!context || !vmi) {
    log_error("STATE_NETWORK_TRACE_CALLBACK: Invalid context or VMI instance");
    return VMI_FAILURE;
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler->is_paused) {
    log_error("STATE_NETWORK_TRACE_CALLBACK: Callback requires a paused VM.");
    return VMI_FAILURE;
  }

  detection_context_t detection_context = {0};

  detection_context.kernel_connections =
      g_array_new(FALSE, TRUE, sizeof(network_connection_t));
  detection_context.suspicious_count = 0;

  // Check netfilter hooks for modifications
  if (check_netfilter_hooks(vmi, &detection_context) != VMI_SUCCESS) {
    log_error("STATE_NETWORK_TRACE_CALLBACK: Failed to check netfilter hooks");
    return VMI_FAILURE;
  }

  // Walk kernel network structures directly
  if (walk_tcp_hash_table(vmi, &detection_context) != VMI_SUCCESS) {
    log_error("STATE_NETWORK_TRACE_CALLBACK: Failed to walk TCP hash tables");
    return VMI_FAILURE;
  }

  if (detection_context.suspicious_count > 0) {
    log_warn(
        "STATE_NETWORK_TRACE_CALLBACK: Found %u suspicious network activities!",
        detection_context.suspicious_count);
  } else {
    log_info("STATE_NETWORK_TRACE_CALLBACK: No immediate threats detected");
  }

  log_info("STATE_NETWORK_TRACE_CALLBACK: CONNECTIONS found: %u kernel",
           detection_context.kernel_connections->len);

  cleanup_detection_context(&detection_context);

  return VMI_SUCCESS;
}
