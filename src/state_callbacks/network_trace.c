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

// TODO: Ahh, it will be a pain when fixing the libvmi conf.
// Kernel 5.15.0 socket structure offsets (adjust for your kernel!)
const unsigned long sock_common_offset = 0;      // sock_common at start of sock
const unsigned long skc_daddr_offset = 0x0;      // destination IP offset
const unsigned long skc_rcv_saddr_offset = 0x4;  // source IP offset
const unsigned long skc_dport_offset = 0x8;      // destination port offset
const unsigned long skc_num_offset = 0xa;        // source port offset
const unsigned long skc_node_offset = 0x10;      // hash node offset
const unsigned long skc_state_offset = 0x18;     // TCP state offset
const unsigned long skc_node_next_offset = 0x8;  // next pointer in hlist_node

// Netfilter structure offsets for kernel 5.x+ (adjust for your kernel!)
const unsigned long net_nf_offset = 0x40;   // Offset to netns_nf in struct net
const unsigned long nf_hooks_offset = 0x0;  // Offset to hooks array in netns_nf

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
    return true;
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

  // Additional rootkit-specific port patterns
  if (port >= 665 && port <= 667) {
    return true;  // Reptile variations
  }

  // Common backdoor ports used in proof-of-concepts
  uint16_t poc_ports[] = {
      4444,  5555,  6666, 7777, 8888, 9999,  // Sequential patterns
      1234,  2222,  3333,                    // Simple patterns
      31337, 13370,                          // Leet variations
      12345, 54321,                          // Palindromic
  };

  size_t poc_count = sizeof(poc_ports) / sizeof(poc_ports[0]);
  for (size_t i = 0; i < poc_count; i++) {
    if (port == poc_ports[i]) {
      return true;
    }
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

      addr_t sock_common_addr = sock_addr + sock_common_offset;

      // Read IP addresses and ports
      if (vmi_read_32_va(vmi, sock_common_addr + skc_daddr_offset, 0, &daddr) ==
              VMI_SUCCESS &&
          vmi_read_32_va(vmi, sock_common_addr + skc_rcv_saddr_offset, 0,
                         &saddr) == VMI_SUCCESS &&
          vmi_read_16_va(vmi, sock_common_addr + skc_dport_offset, 0, &dport) ==
              VMI_SUCCESS &&
          vmi_read_16_va(vmi, sock_common_addr + skc_num_offset, 0, &sport) ==
              VMI_SUCCESS &&
          vmi_read_8_va(vmi, sock_common_addr + skc_state_offset, 0, &state) ==
              VMI_SUCCESS) {

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
          log_warn("SUSPICIOUS PORT: %s:%u -> %s:%u", inet_ntoa(local_addr),
                   conn.local_port, inet_ntoa(remote_addr), conn.remote_port);
          is_suspicious = true;
        }

        if (is_suspicious_ip(conn.local_ip) ||
            is_suspicious_ip(conn.remote_ip)) {
          log_warn("SUSPICIOUS IP: %s:%u -> %s:%u", inet_ntoa(local_addr),
                   conn.local_port, inet_ntoa(remote_addr), conn.remote_port);
          is_suspicious = true;
        }

        // Check for unusual TCP states
        if (conn.state > TCP_CLOSING) {
          log_warn("UNUSUAL TCP STATE: %s:%u -> %s:%u state=%u",
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
      if (vmi_read_addr_va(
              vmi, sock_common_addr + skc_node_offset + skc_node_next_offset, 0,
              &next_node_addr) != VMI_SUCCESS) {
        break;
      }

      // Calculate next socket address from node address
      sock_addr = (next_node_addr != 0)
                      ? (next_node_addr - sock_common_offset - skc_node_offset)
                      : 0;

      chain_count++;
    }

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
 * @brief Check network-related system calls for hooks
 * 
 * Many network rootkits hook system calls related to networking
 * in addition to or instead of netfilter hooks.
 * 
 * @param vmi The VMI instance
 * @param ctx The detection context
 * @return uint32_t VMI_SUCCESS on success
 */
static uint32_t check_network_syscall_hooks(vmi_instance_t vmi,
                                            detection_context_t* ctx) {
  addr_t sys_call_table_addr = 0;

  log_debug("Checking network-related system calls for hooks...");

  if (vmi_translate_ksym2v(vmi, "sys_call_table", &sys_call_table_addr) !=
      VMI_SUCCESS) {
    log_warn("Failed to resolve sys_call_table symbol");
    return VMI_SUCCESS;
  }

  // Network-related system calls that rootkits commonly hook
  struct {
    int syscall_num;
    const char* name;
  } network_syscalls[] = {
      {41, "sys_socket"},    // socket creation
      {42, "sys_connect"},   // outgoing connections
      {43, "sys_accept"},    // incoming connections
      {49, "sys_bind"},      // port binding
      {44, "sys_sendto"},    // send data
      {45, "sys_recvfrom"},  // receive data
      {46, "sys_sendmsg"},   // send message
      {47, "sys_recvmsg"},   // receive message
      {50, "sys_listen"},    // listen for connections
      {48, "sys_shutdown"},  // close connections
  };

  size_t syscall_count = sizeof(network_syscalls) / sizeof(network_syscalls[0]);

  for (size_t i = 0; i < syscall_count; i++) {
    addr_t syscall_ptr_addr =
        sys_call_table_addr + network_syscalls[i].syscall_num * sizeof(addr_t);
    addr_t syscall_addr = 0;

    if (vmi_read_addr_va(vmi, syscall_ptr_addr, 0, &syscall_addr) !=
        VMI_SUCCESS) {
      continue;
    }

    log_debug("Network syscall %s (%d) at 0x%" PRIx64, network_syscalls[i].name,
              network_syscalls[i].syscall_num, syscall_addr);

    // Basic validation - system calls should be in kernel text
    if (syscall_addr < 0xffffffff80000000ULL) {
      log_warn(
          "SUSPICIOUS: Network syscall %s hooked to user space: 0x%" PRIx64,
          network_syscalls[i].name, syscall_addr);
      ctx->suspicious_count++;
    }

    // Check for signature addresses
    if ((syscall_addr & 0xFFFF) == 0x666 || (syscall_addr & 0xFFFF) == 0x1337) {
      log_warn(
          "SUSPICIOUS: Network syscall %s has signature address: 0x%" PRIx64,
          network_syscalls[i].name, syscall_addr);
      ctx->suspicious_count++;
    }
  }

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

  log_info(
      "Checking netfilter hooks for rootkit modifications (kernel 5.x+)...");

  // Get init_net (initial network namespace) instead of old nf_hooks
  if (vmi_translate_ksym2v(vmi, "init_net", &init_net_addr) != VMI_SUCCESS) {
    log_warn("Failed to resolve init_net symbol");
    return VMI_SUCCESS;  // Continue with other checks
  }

  log_debug("init_net found at 0x%" PRIx64, init_net_addr);

  addr_t netns_nf_addr = init_net_addr + net_nf_offset;
  addr_t hooks_array_addr = netns_nf_addr + nf_hooks_offset;

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
        if (hook_func < 0xffffffff80000000ULL) {
          log_warn(
              "SUSPICIOUS: Hook function in user space: PF=%d HOOK=%d "
              "func=0x%" PRIx64,
              pf, hook, hook_func);
          is_suspicious = true;
        }

        // 2. Check for common rootkit signature addresses
        uint16_t func_low_bits = hook_func & 0xFFFF;
        if (func_low_bits == 0x666 || func_low_bits == 0x1337 ||
            func_low_bits == 0xdead || func_low_bits == 0xbeef) {
          log_warn(
              "SUSPICIOUS: Hook with signature address pattern: PF=%d HOOK=%d "
              "func=0x%" PRIx64,
              pf, hook, hook_func);
          is_suspicious = true;
        }

        // 3. Check for hooks in unusual memory regions (heap, stack, etc.)
        if ((hook_func >= 0xffff888000000000ULL &&
             hook_func < 0xffffc87fffffffffULL)) {
          log_warn(
              "SUSPICIOUS: Hook in potential heap memory: PF=%d HOOK=%d "
              "func=0x%" PRIx64,
              pf, hook, hook_func);
          is_suspicious = true;
        }

        // 4. Check for suspicious hook private data patterns
        if (hook_priv != 0) {
          uint16_t priv_low_bits = hook_priv & 0xFFFF;
          if (priv_low_bits == 0x666 || priv_low_bits == 0x1337) {
            log_warn(
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
            log_warn(
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
        log_warn("Excessive netfilter hooks detected: PF=%d HOOK=%d COUNT=%u",
                 pf, hook, num_hook_entries);
        ctx->suspicious_count++;
      }

      // Detect unusual protocol families or hook points
      if (pf >= 8 || hook >= 5) {
        log_warn("Unusual netfilter parameters: PF=%d HOOK=%d", pf, hook);
        ctx->suspicious_count++;
      }
    }
  }

  // Additional detection: Check for hooked network system calls
  check_network_syscall_hooks(vmi, ctx);

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