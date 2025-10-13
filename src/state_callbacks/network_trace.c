#include "state_callbacks/network_trace.h"
#include <arpa/inet.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <log.h>
#include <string.h>
#include "event_handler.h"
#include "offsets.h"
#include "state_callbacks/responses/network_trace_response.h"
#include "utils.h"

// TCP states: *only* need max valid state for filtering
#define TCP_MAX_VALID_STATE 12  // TCP_NEW_SYN_RECV

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
  uint32_t state;        ///< State (tcp_state_t).
  vmi_pid_t pid;         ///< Process ID associated with the connection.
  addr_t sock_addr;      ///< Socket address in kernel memory.
} network_connection_t;

/**
 * @brief Context for network detection operations.
 * 
 * This structure holds the state and results of network tracing.
 */
typedef struct {
  GArray* kernel_connections;  ///< Direct kernel connections.
} detection_context_t;

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
    log_debug("Public IP detected: %u.%u.%u.%u.", octets[0], octets[1],
              octets[2], octets[3]);
    return true;
  }

  // Check for unusual patterns (all same octets)
  if (octets[0] == octets[1] && octets[1] == octets[2] &&
      octets[2] == octets[3]) {
    return true;
  }

  return false;
}

/**
 * @brief Walk the TCP established connections hash table to find active connections.
 * 
 * @param vmi The VMI instance.
 * @param ctx The detection context containing state and results.
 * @return uint32_t VMI_SUCCESS on success, VMI_FAILURE on error.
 */
static uint32_t walk_tcp_established_hash_table(vmi_instance_t vmi,
                                                detection_context_t* ctx) {
  addr_t tcp_hashinfo_addr = 0;
  addr_t ehash = 0;
  uint32_t ehash_mask = 0;

  // Get tcp_hashinfo global symbol
  if (vmi_translate_ksym2v(vmi, "tcp_hashinfo", &tcp_hashinfo_addr) !=
      VMI_SUCCESS) {
    log_error("Failed to resolve tcp_hashinfo global symbol.");
    return VMI_FAILURE;
  }

  log_info("tcp_hashinfo resolved at 0x%" PRIx64, tcp_hashinfo_addr);

  // Read ehash pointer and mask
  if (vmi_read_addr_va(vmi,
                       tcp_hashinfo_addr + LINUX_INET_HASHINFO_EHASH_OFFSET, 0,
                       &ehash) != VMI_SUCCESS ||
      vmi_read_32_va(vmi,
                     tcp_hashinfo_addr + LINUX_INET_HASHINFO_EHASH_MASK_OFFSET,
                     0, &ehash_mask) != VMI_SUCCESS) {
    log_error("Failed to read TCP established hash table info.");
    log_error("tcp_hashinfo_addr=0x%" PRIx64
              ", ehash_offset=0x%x, mask_offset=0x%x",
              tcp_hashinfo_addr, LINUX_INET_HASHINFO_EHASH_OFFSET,
              LINUX_INET_HASHINFO_EHASH_MASK_OFFSET);
    return VMI_FAILURE;
  }

  if (ehash == 0) {
    log_error("ERROR: ehash is NULL - hash table not initialized!");
    return VMI_FAILURE;
  }

  log_info("TCP established hash table: ehash=0x%" PRIx64
           " mask=0x%x (scanning %u buckets)",
           ehash, ehash_mask, ehash_mask + 1);

  uint32_t non_empty_buckets = 0;

  // inet_ehash_bucket layout (x86_64): hlist_nulls_head (first pointer @ +0)
  const addr_t ehash_bucket_stride =
      LINUX_INET_EHASH_BUCKET_SIZE;  // sizeof(struct inet_ehash_bucket)
  const addr_t chain_first_offset =
      LINUX_INET_EHASH_BUCKET_CHAIN_OFFSET +
      LINUX_HLIST_NULLS_HEAD_FIRST_OFFSET;  // offsetof(bucket, chain.first)
  const addr_t nulls_mark = 1ULL;           // hlist_nulls tag bit in LSB

  // Walk through each bucket in the established hash table
  for (uint32_t i = 0; i <= ehash_mask; i++) {
    addr_t bucket_addr = ehash + (i * ehash_bucket_stride);

    // Read chain.first (may be NULLS-marked)
    addr_t first_ptr = 0;
    if (vmi_read_addr_va(vmi, bucket_addr + chain_first_offset, 0,
                         &first_ptr) != VMI_SUCCESS) {
      log_warn("Failed to read established hash bucket %u at 0x%" PRIx64, i,
               bucket_addr);
      continue;
    }

    // Empty bucket? (hlist_nulls encodes end as NULLS-marked pointer)
    if ((first_ptr == 0) || (first_ptr & nulls_mark)) {
      continue;
    }

    non_empty_buckets++;
    log_debug("Established hash bucket %u: head=0x%" PRIx64, i, first_ptr);

    // Walk the linked list in this bucket
    addr_t node_addr =
        first_ptr &
        ~nulls_mark;  // address of struct hlist_nulls_node inside skc_node
    uint32_t chain_count = 0;

    while (node_addr != 0 && chain_count < 1000) {  // Prevent infinite loops
      // node_addr points to sock_common.skc_node (hlist_nulls_node at offset LINUX_SKC_NODE_OFFSET)
      addr_t sock_common_addr = node_addr - LINUX_SKC_NODE_OFFSET;

      // Check socket family first (at LINUX_SKC_FAMILY_OFFSET)
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, sock_common_addr + LINUX_SKC_FAMILY_OFFSET, 0,
                         &family) != VMI_SUCCESS) {
        log_warn("Failed to read socket family at 0x%" PRIx64,
                 sock_common_addr + LINUX_SKC_FAMILY_OFFSET);
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
        if (state == 0 || state > TCP_MAX_VALID_STATE) {
          // Advance to next node
          addr_t next_ptr = 0;
          if (vmi_read_addr_va(vmi, node_addr, 0, &next_ptr) != VMI_SUCCESS)
            break;
          if (next_ptr & nulls_mark)
            break;
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
          node_addr = next_ptr & ~nulls_mark;
          chain_count++;
          continue;
        }

        // Convert network byte order to host byte order
        uint32_t laddr = ntohl(saddr_be);
        uint32_t raddr = ntohl(daddr_be);
        uint16_t lport = sport_host;  // skc_num is already in host byte order
        uint16_t rport = ntohs(dport_be);

        // Create connection structure
        network_connection_t conn = {0};
        conn.local_ip = laddr;
        conn.remote_ip = raddr;
        conn.local_port = lport;
        conn.remote_port = rport;
        conn.state = state;
        conn.sock_addr = sock_common_addr;

        // Convert IP addresses to strings for logging
        char laddr_str[INET_ADDRSTRLEN];
        char raddr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &laddr, laddr_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &raddr, raddr_str, INET_ADDRSTRLEN);

        log_info("TCP connection: %s:%u -> %s:%u state=%u", laddr_str,
                 conn.local_port, raddr_str, conn.remote_port, conn.state);
        g_array_append_val(ctx->kernel_connections, conn);
      } else {
        log_warn("Failed to read established socket data at 0x%" PRIx64,
                 sock_common_addr);
      }

      // Advance to next node
      addr_t next_ptr = 0;
      if (vmi_read_addr_va(vmi, node_addr, 0, &next_ptr) != VMI_SUCCESS)
        break;
      if (next_ptr & nulls_mark)
        break;
      node_addr = next_ptr & ~nulls_mark;
      chain_count++;
    }

    if (chain_count >= 1000) {
      log_warn(
          "Established hash bucket %u: Chain too long, stopping at 1000 nodes",
          i);
    }
  }

  log_info(
      "TCP established hash table: %u buckets, %u non-empty, %u connections "
      "found",
      ehash_mask + 1, non_empty_buckets, ctx->kernel_connections->len);

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
    return log_error_and_queue_response_task(
        "network_trace_state", STATE_NETWORK_TRACE, INVALID_ARGUMENTS,
        "STATE_NETWORK_TRACE: Invalid context or VMI instance");
  }

  event_handler_t* event_handler = (event_handler_t*)context;
  if (!event_handler->is_paused) {
    return log_error_and_queue_response_task(
        "network_trace_state", STATE_NETWORK_TRACE, INVALID_ARGUMENTS,
        "STATE_NETWORK_TRACE: Callback requires a valid event handler context");
  }

  log_info(
      "Executing STATE_NETWORK_TRACE callback - scanning established TCP "
      "connections only (no UDP, no listening sockets).");

  // Create network trace state data structure
  network_trace_state_data_t* network_data = network_trace_state_data_new();
  if (!network_data) {
    return log_error_and_queue_response_task(
        "network_trace_state", STATE_NETWORK_TRACE, MEMORY_ALLOCATION_FAILURE,
        "STATE_NETWORK_TRACE: Failed to allocate memory for network trace "
        "state data");
  }

  detection_context_t detection_context = {0};
  detection_context.kernel_connections =
      g_array_new(FALSE, TRUE, sizeof(network_connection_t));

  // Walk TCP established hash table and add connections to data structure
  if (walk_tcp_established_hash_table(vmi, &detection_context) != VMI_SUCCESS) {
    log_warn(
        "STATE_NETWORK_TRACE: Failed to walk TCP established hash tables, "
        "continuing...");
  }

  // Convert detection context data to response data structure
  uint32_t suspicious_connections = 0;

  // Process TCP connections
  for (guint i = 0; i < detection_context.kernel_connections->len; i++) {
    network_connection_t* conn = &g_array_index(
        detection_context.kernel_connections, network_connection_t, i);

    // Convert IP addresses to strings
    struct in_addr laddr = {.s_addr = htonl(conn->local_ip)};
    struct in_addr raddr = {.s_addr = htonl(conn->remote_ip)};
    char laddr_str[INET_ADDRSTRLEN], raddr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &laddr, laddr_str, sizeof(laddr_str));
    inet_ntop(AF_INET, &raddr, raddr_str, sizeof(raddr_str));

    // Check if connection is suspicious
    bool is_suspicious = false;
    if (is_suspicious_port(conn->local_port) ||
        is_suspicious_port(conn->remote_port)) {
      is_suspicious = true;
    }
    if (is_suspicious_ip(conn->local_ip) || is_suspicious_ip(conn->remote_ip)) {
      is_suspicious = true;
    }

    if (is_suspicious) {
      suspicious_connections++;
    }

    // Convert state to hex string
    char state_str[8];
    (void)snprintf(state_str, sizeof(state_str), "%02X", conn->state);

    // Convert inode to string (placeholder since we don't have it in the original structure)
    char inode_str[16];
    (void)snprintf(inode_str, sizeof(inode_str), "%lu",
                   (unsigned long)conn->sock_addr);

    network_trace_state_add_tcp_socket(
        network_data, laddr_str, conn->local_port, raddr_str, conn->remote_port,
        state_str, inode_str, is_suspicious);
  }

  // Set summary information
  network_trace_state_set_summary(
      network_data, detection_context.kernel_connections->len,
      suspicious_connections,
      0,   // total_hooks - removed netfilter hooks
      0);  // suspicious_hooks - removed netfilter hooks

  log_info("STATE_NETWORK_TRACE: No immediate threats detected");

  log_info("STATE_NETWORK_TRACE: ESTABLISHED TCP CONNECTIONS found: %u",
           detection_context.kernel_connections->len);

  // Clean up detection context
  cleanup_detection_context(&detection_context);

  log_info("STATE_NETWORK_TRACE callback completed.");

  return log_success_and_queue_response_task(
      "network_trace_state", STATE_NETWORK_TRACE, network_data,
      (void (*)(void*))network_trace_state_data_free);
}