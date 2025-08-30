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
  TCP_CLOSING = 11,
  TCP_NEW_SYN_RECV = 12
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
 * @note https://elixir.bootlin.com/linux/v5.15.139/source/include/net/tcp_states.h#L13
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
    case TCP_NEW_SYN_RECV:
      return "NEW_SYN_RECV";
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
      // log_debug("Suspicious port detected: %u", port);
      return true;
    }
  }

  // High ports that are unusual for legitimate services.
  if (port >= 60000 && port <= 65534) {
    // log_debug("High range suspicious port detected: %u", port);
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

  // Pass network order to ipv4_is_public (it expects ip_be)
  if (ipv4_is_public(htonl(ip_addr))) {
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

  // Read ehash pointer and mask
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

  // inet_ehash_bucket layout (x86_64): spinlock (8 bytes) + hlist_nulls_head (first pointer @ +8)
  const addr_t ehash_bucket_stride = 16;  // sizeof(struct inet_ehash_bucket)
  const addr_t chain_first_offset = 8;    // offsetof(bucket, chain.first)
  const addr_t nulls_mark = 1ULL;         // hlist_nulls tag bit in LSB

  for (uint32_t i = 0; i <= ehash_mask; i++) {
    addr_t bucket_addr = ehash + (i * ehash_bucket_stride);

    // Read chain.first (may be NULLS-marked)
    addr_t first_ptr = 0;
    if (vmi_read_addr_va(vmi, bucket_addr + chain_first_offset, 0,
                         &first_ptr) != VMI_SUCCESS)
      continue;

    // Empty bucket?  (hlist_nulls encodes end as NULLS-marked pointer)
    if ((first_ptr == 0) || (first_ptr & nulls_mark))
      continue;

    addr_t node_addr =
        first_ptr &
        ~nulls_mark;  // address of struct hlist_nulls_node inside skc_node
    addr_t prev_node_addr = 0;  // For loop detection
    int chain_count = 0;

    while (node_addr && chain_count < 1000) {
      // node_addr points to sock_common.skc_node (hlist_nulls_node at offset LINUX_SKC_NODE_OFFSET)
      addr_t sock_common_addr = node_addr - LINUX_SKC_NODE_OFFSET;

      // Check socket family first (at offset 0x10)
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, sock_common_addr + 0x10, 0, &family) !=
          VMI_SUCCESS) {
        break;  // Failed to read, stop processing this chain
      }

      // Skip non-IPv4 sockets
      if (family != 2) {  // AF_INET = 2
        // Advance to next node
        addr_t next_ptr = 0;
        if (vmi_read_addr_va(vmi, node_addr, 0, &next_ptr) != VMI_SUCCESS)
          break;
        if (next_ptr & nulls_mark)
          break;
        prev_node_addr = node_addr;
        node_addr = next_ptr & ~nulls_mark;
        chain_count++;
        continue;
      }

      // Extract connection information
      uint32_t daddr_be = 0, saddr_be = 0;
      uint16_t dport_be = 0, sport_host = 0;
      uint8_t state = 0;

      if (vmi_read_32_va(vmi, sock_common_addr + LINUX_SKC_DADDR_OFFSET, 0,
                         &daddr_be) == VMI_SUCCESS &&
          vmi_read_32_va(vmi, sock_common_addr + LINUX_SKC_RCV_SADDR_OFFSET, 0,
                         &saddr_be) == VMI_SUCCESS &&
          vmi_read_16_va(vmi, sock_common_addr + LINUX_SKC_DPORT_OFFSET, 0,
                         &dport_be) == VMI_SUCCESS &&
          vmi_read_16_va(vmi, sock_common_addr + LINUX_SKC_NUM_OFFSET, 0,
                         &sport_host) == VMI_SUCCESS &&
          vmi_read_8_va(vmi, sock_common_addr + LINUX_SKC_STATE_OFFSET, 0,
                        &state) == VMI_SUCCESS) {

        // Skip invalid/uninitialized connections
        if (state == 0 || state > TCP_NEW_SYN_RECV) {
          // Advance to next node
          addr_t next_ptr = 0;
          if (vmi_read_addr_va(vmi, node_addr, 0, &next_ptr) != VMI_SUCCESS)
            break;
          if (next_ptr & nulls_mark)
            break;
          prev_node_addr = node_addr;
          node_addr = next_ptr & ~nulls_mark;
          chain_count++;
          continue;
        }

        // Skip completely empty entries
        if (daddr_be == 0 && saddr_be == 0 && dport_be == 0 &&
            sport_host == 0) {
          // Advance to next node
          addr_t next_ptr = 0;
          if (vmi_read_addr_va(vmi, node_addr, 0, &next_ptr) != VMI_SUCCESS)
            break;
          if (next_ptr & nulls_mark)
            break;
          prev_node_addr = node_addr;
          node_addr = next_ptr & ~nulls_mark;
          chain_count++;
          continue;
        }

        network_connection_t conn = {0};
        conn.sock_addr =
            sock_common_addr;  // store common base (useful for later)
        conn.remote_ip = ntohl(daddr_be);    // host order for printing
        conn.local_ip = ntohl(saddr_be);     // host order
        conn.remote_port = ntohs(dport_be);  // host order
        conn.local_port = sport_host;        // skc_num is already host order
        conn.state = state;

        struct in_addr laddr = {.s_addr = htonl(conn.local_ip)};
        struct in_addr raddr = {.s_addr = htonl(conn.remote_ip)};
        char laddr_str[INET_ADDRSTRLEN], raddr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &laddr, laddr_str, sizeof(laddr_str));
        inet_ntop(AF_INET, &raddr, raddr_str, sizeof(raddr_str));
        log_debug("TCP connection: %s:%u -> %s:%u state=%s", laddr_str,
                  conn.local_port, raddr_str, conn.remote_port,
                  tcp_state_to_string((tcp_state_t)conn.state));

        bool suspicious = false;

        // Ports
        if (is_suspicious_port(conn.local_port) ||
            is_suspicious_port(conn.remote_port)) {
          inet_ntop(AF_INET, &laddr, laddr_str, sizeof(laddr_str));
          inet_ntop(AF_INET, &raddr, raddr_str, sizeof(raddr_str));
          log_debug("Suspicious Port: %s:%u -> %s:%u", laddr_str,
                    conn.local_port, raddr_str, conn.remote_port);
          suspicious = true;
        }

        // IPs — use network-order addresses for public check
        if (ipv4_is_public(saddr_be) || ipv4_is_public(daddr_be)) {
          inet_ntop(AF_INET, &laddr, laddr_str, sizeof(laddr_str));
          inet_ntop(AF_INET, &raddr, raddr_str, sizeof(raddr_str));
          log_debug("Suspicious IP (public): %s:%u -> %s:%u", laddr_str,
                    conn.local_port, raddr_str, conn.remote_port);
          suspicious = true;
        }

        // State sanity (optional)
        // Note: We already filtered state==0 and state > TCP_NEW_SYN_RECV above

        if (suspicious)
          ctx->suspicious_count++;

        g_array_append_val(ctx->kernel_connections, conn);
      }

      // Advance to next node in the hlist_nulls chain
      addr_t next_ptr = 0;
      if (vmi_read_addr_va(vmi,
                           node_addr /* + offsetof(hlist_nulls_node, next)=0 */,
                           0, &next_ptr) != VMI_SUCCESS)
        break;

      if (next_ptr & nulls_mark)
        break;

      // Loop detection
      if (next_ptr == node_addr || next_ptr == prev_node_addr) {
        log_debug("Loop detected in bucket %u", i);
        break;
      }

      prev_node_addr = node_addr;
      node_addr =
          next_ptr & ~nulls_mark;  // <- mask tag bit before using pointer
      chain_count++;
    }

    if (chain_count >= 100) {
      log_debug("Excessive socket chain in bucket %u: %d connections", i,
                chain_count);
      ctx->suspicious_count++;
    }
  }

  log_debug("Completed TCP hash table walk, found %u connections",
            ctx->kernel_connections->len);

  return VMI_SUCCESS;
}

/**
 * @brief Check netfilter hooks for modifications (Kernel 5.x+ compatible).
 * 
 * @note In kernel 5.x+, netfilter hooks are stored per-netns in struct net
 * instead of the global nf_hooks array that existed in older kernels.
 * 
 * @param vmi The VMI instance.
 * @param ctx The detection context containing state and results.
 * @return uint32_t VMI_SUCCESS on success, VMI_FAILURE on error.
 */
static uint32_t check_netfilter_hooks(vmi_instance_t vmi,
                                      detection_context_t* ctx) {
  addr_t init_net_addr = 0;

  if (vmi_translate_ksym2v(vmi, "init_net", &init_net_addr) != VMI_SUCCESS) {
    log_debug("Failed to resolve init_net symbol");
    return VMI_FAILURE;
  }

  addr_t netns_nf_addr = init_net_addr + LINUX_NET_NF_OFFSET;
  log_debug("init_net @ 0x%" PRIx64 " netns_nf @ 0x%" PRIx64, init_net_addr,
            netns_nf_addr);

  struct {
    const char* name;
    size_t offset;
    int count;
  } hook_arrays[] = {
      {"IPv4", LINUX_NETNF_HOOKS_IPV4_OFFSET, 5},
      {"IPv6", LINUX_NETNF_HOOKS_IPV6_OFFSET, 5},
      {"ARP", LINUX_NETNF_HOOKS_ARP_OFFSET, 3},
      {"Bridge", LINUX_NETNF_HOOKS_BRIDGE_OFFSET, 5},
  };

  for (size_t arr = 0; arr < sizeof(hook_arrays) / sizeof(hook_arrays[0]);
       arr++) {
    for (int hook = 0; hook < hook_arrays[arr].count; hook++) {
      addr_t hook_entries_addr = 0;
      addr_t slot_addr =
          netns_nf_addr + hook_arrays[arr].offset + hook * sizeof(addr_t);

      if (vmi_read_addr_va(vmi, slot_addr, 0, &hook_entries_addr) !=
          VMI_SUCCESS)
        continue;
      if (!hook_entries_addr)
        continue;

      uint16_t num_hook_entries = 0;
      if (vmi_read_16_va(vmi, hook_entries_addr + NF_HOOK_ENTRIES_NUM_OFFSET, 0,
                         &num_hook_entries) != VMI_SUCCESS)
        continue;

      if (num_hook_entries == 0 || num_hook_entries > 100)
        continue;

      log_debug("%s HOOK=%d -> %u entries @ 0x%" PRIx64, hook_arrays[arr].name,
                hook, num_hook_entries, hook_entries_addr);

      addr_t hooks_start = hook_entries_addr + NF_HOOK_ENTRIES_PAD;

      for (uint16_t i = 0; i < num_hook_entries; i++) {
        addr_t entry_addr = hooks_start + i * NF_HOOK_ENTRY_SIZE;
        addr_t hook_func = 0, hook_priv = 0;

        if (vmi_read_addr_va(vmi, entry_addr, 0, &hook_func) != VMI_SUCCESS ||
            vmi_read_addr_va(vmi, entry_addr + 8, 0, &hook_priv) != VMI_SUCCESS)
          continue;

        if (!hook_func)
          continue;

        log_debug("%s HOOK=%d entry[%u]: func=0x%" PRIx64 " priv=0x%" PRIx64,
                  hook_arrays[arr].name, hook, i, hook_func, hook_priv);

        bool suspicious = false;

        // Correct logic: suspicious if NOT in kernel text
        if (!is_in_kernel_text(vmi, hook_func)) {
          log_debug(
              "SUSPICIOUS: %s HOOK=%d func outside kernel text @ 0x%" PRIx64,
              hook_arrays[arr].name, hook, hook_func);
          suspicious = true;
        }

        if (suspicious)
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
    ctx->kernel_connections = NULL;
  }
}

uint32_t state_network_trace_callback(vmi_instance_t vmi, void* context) {
  // Preconditions
  if (!context || !vmi) {
    log_error("STATE_NETWORK_TRACE_CALLBACK: Invalid context or VMI instance");
    return VMI_FAILURE;
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler->is_paused) {
    log_error("STATE_NETWORK_TRACE_CALLBACK: Callback requires a paused VM.");
    return VMI_FAILURE;
  }

  log_info("Executing STATE_NETWORK_TRACE_CALLBACK callback.");

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
        "STATE_NETWORK_TRACE_CALLBACK: Found %u suspicious network "
        "activities!",
        detection_context.suspicious_count);
  } else {
    log_info("STATE_NETWORK_TRACE_CALLBACK: No immediate threats detected");
  }

  log_info("STATE_NETWORK_TRACE_CALLBACK: CONNECTIONS found: %u kernel",
           detection_context.kernel_connections->len);

  cleanup_detection_context(&detection_context);

  log_info("STATE_NETWORK_TRACE callback completed.");

  return VMI_SUCCESS;
}
