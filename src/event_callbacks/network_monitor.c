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
 * @brief Extract and log function-specific network information with security context
 * 
 * This function provides detailed logging of network operations intercepted via VMI breakpoints.
 * It extracts meaningful information from kernel function arguments and provides security context
 * for each operation. This is crucial for detecting rootkit network activity, backdoors, and
 * unauthorized network modifications.
 * 
 * Key concepts and references:
 * - Socket flags: SOCK_NONBLOCK (0x800), SOCK_CLOEXEC (0x80000) - see include/uapi/linux/net.h
 * - Address families: AF_INET (2), AF_INET6 (10) - see include/uapi/linux/socket.h
 * - Socket structures: sockaddr_in (IPv4), sockaddr_in6 (IPv6) - see include/uapi/linux/in.h
 * - Port ranges: Well-known (0-1023), Registered (1024-49151), Dynamic (49152-65535) - IANA/RFC 6335
 * - Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 - RFC 1918>
 * - Netfilter hooks: NF_INET_* constants - see include/uapi/linux/netfilter.h
 * - TCP shutdown: SHUT_RD (0), SHUT_WR (1), SHUT_RDWR (2) - see include/uapi/linux/net.h
 * - Breakpoint instruction: INT3 (0xCC) - Intel x86-64 architecture
 * 
 * @param vmi VMI instance for memory access
 * @param func_name Name of the network function being called
 * @param arg1 First argument (RDI) - function-specific
 * @param arg2 Second argument (RSI) - function-specific  
 * @param arg3 Third argument (RDX) - function-specific
 * @param kaddr Kernel address where breakpoint was hit
 * 
 * @see Linux Kernel Documentation:
 *  Socket API: https://www.kernel.org/doc/html/latest/networking/socket.html
 *  TCP Implementation: https://www.kernel.org/doc/html/latest/networking/tcp.html
 *  Netfilter Framework: https://www.netfilter.org/documentation/
 *  Network Device API: https://www.kernel.org/doc/html/latest/networking/netdev.html
 *  IANA Port Registry: https://www.iana.org/assignments/service-names-port-numbers/
 *  RFC 1918 (Private Address Space): https://tools.ietf.org/html/rfc1918
 *  RFC 6335 (Port Numbering): https://tools.ietf.org/html/rfc6335
 */
static void log_network_function_info(vmi_instance_t vmi, const char* func_name,
                                      uint64_t arg1, uint64_t arg2,
                                      uint64_t arg3, uint64_t kaddr) {
  if (!func_name) {
    log_debug("INTERRUPT_NETWORK_MONITOR: Unknown function @0x%" PRIx64, kaddr);
    return;
  }

  if (strstr(func_name, "inet_bind")) {

    log_info(
        "INTERRUPT_NETWORK_MONITOR: inet_bind() called - Socket binding "
        "operation");
    log_info("  Socket: 0x%" PRIx64 ", Address: 0x%" PRIx64
             ", Length: %" PRIu64,
             arg1, arg2, arg3);
    log_info(
        "  Function: Associates a socket with a specific network address and "
        "port");
    if (arg2 != 0 && arg3 >= 2) {
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, arg2, 0, &family) == VMI_SUCCESS) {
        if (family == AF_INET &&
            arg3 >= 8) {  // IPv4 sockaddr_in - see include/uapi/linux/in.h
          uint16_t port = 0;
          uint32_t ip_addr = 0;
          if (vmi_read_16_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_PORT_OFFSET, 0,
                             &port) == VMI_SUCCESS &&
              vmi_read_32_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_ADDR_OFFSET, 0,
                             &ip_addr) == VMI_SUCCESS) {
            struct in_addr addr = {.s_addr = ip_addr};
            uint16_t host_port = ntohs(port);

            log_info("  Binding to: %s:%u", inet_ntoa(addr), host_port);
            if (host_port < 1024) {  // Well-known ports (0-1023) - IANA
              log_info("  Port %u: Privileged port (requires root privileges)",
                       host_port);
              // Registered ports (1024-49151) - IANA
            } else if (host_port >= 1024 && host_port < 49152) {
              log_info("  Port %u: Registered port range", host_port);
              // Dynamic/private ports (49152-65535) - RFC 6335
            } else if (host_port >= 49152) {
              log_info("  Port %u: Dynamic/private port range", host_port);
            }

            if (ip_addr == 0) {
              log_info(
                  "  IP: INADDR_ANY (0.0.0.0) - binding to all available "
                  "interfaces");
            } else if (ip_addr == 0x7F000001) {  // 127.0.0.1 - INADDR_LOOPBACK
              log_info(
                  "  IP: localhost (127.0.0.1) - binding to loopback interface "
                  "only");
            } else if ((ip_addr & 0xFF000000) ==
                       0x0A000000) {  // 10.0.0.0/8 - RFC 1918
              log_info("  IP: Private network (10.0.0.0/8)");
            } else if ((ip_addr & 0xFFF00000) ==
                       0xAC100000) {  // 172.16.0.0/12 - RFC 1918
              log_info("  IP: Private network (172.16.0.0/12)");
            } else if ((ip_addr & 0xFFFF0000) ==
                       0xC0A80000) {  // 192.168.0.0/16 - RFC 1918
              log_info("  IP: Private network (192.168.0.0/16)");
            } else {
              log_info("  IP: Public/external address");
            }
          }
        } else if (
            family == AF_INET6 &&
            arg3 >= 28) {  // IPv6 sockaddr_in6 - see include/uapi/linux/in6.h
          log_info("  IPv6 binding detected (family: %u)", family);
        }
      }
    }
  } else if (strstr(func_name, "inet_listen")) {

    log_info(
        "INTERRUPT_NETWORK_MONITOR: inet_listen() called - Socket listening "
        "setup");
    log_info("  Socket: 0x%" PRIx64 ", Backlog: %" PRIu64, arg1, arg2);
    log_info("  Function: Enables socket to accept incoming connections");
    if (arg2 == 0) {
      log_info("  Backlog: 0 (system default will be used)");
    } else if (arg2 < 10) {
      log_info("  Backlog: %" PRIu64 " (small queue)", arg2);
    } else if (arg2 < 100) {
      log_info("  Backlog: %" PRIu64 " (moderate queue)", arg2);
    } else {
      log_info("  Backlog: %" PRIu64 " (large queue)", arg2);
    }
  } else if (strstr(func_name, "inet_accept")) {

    log_info(
        "INTERRUPT_NETWORK_MONITOR: inet_accept() called - Connection "
        "acceptance");
    log_info("  Listen socket: 0x%" PRIx64 ", New socket: 0x%" PRIx64
             ", Flags: %" PRIu64,
             arg1, arg2, arg3);
    log_info("  Function: Accepts incoming connection from listening socket");

    if (arg3 & 0x800) {  // SOCK_NONBLOCK
      log_info("  Flag: SOCK_NONBLOCK (non-blocking operation)");
    }
    if (arg3 & 0x80000) {  // SOCK_CLOEXEC
      log_info("  Flag: SOCK_CLOEXEC (close on exec)");
    }
    if (arg3 == 0) {
      log_info("  Flags: None (blocking operation)");
    }
  } else if (strstr(func_name, "tcp_connect")) {

    log_info(
        "INTERRUPT_NETWORK_MONITOR: tcp_connect() called - TCP connection "
        "establishment");
    log_info("  Socket: 0x%" PRIx64 ", Address: 0x%" PRIx64
             ", Length: %" PRIu64,
             arg1, arg2, arg3);
    log_info("  Function: Initiates TCP connection to remote host");

    if (arg1 != 0) {
      addr_t skc_addr = (addr_t)arg1;

      uint16_t src_port = 0;
      if (vmi_read_16_va(vmi, skc_addr + LINUX_SKC_NUM_OFFSET, 0, &src_port) ==
          VMI_SUCCESS) {
        uint16_t host_src_port = ntohs(src_port);

        uint32_t src_ip = 0;
        if (vmi_read_32_va(vmi, skc_addr + LINUX_SKC_RCV_SADDR_OFFSET, 0,
                           &src_ip) == VMI_SUCCESS) {
          struct in_addr src_addr = {.s_addr = src_ip};

          log_info("  Source: %s:%u", inet_ntoa(src_addr), host_src_port);

          if ((src_ip & 0xFF000000) == 0x0A000000) {
            log_info("  Source network: Private (10.0.0.0/8)");
          } else if ((src_ip & 0xFFF00000) == 0xAC100000) {
            log_info("  Source network: Private (172.16.0.0/12)");
          } else if ((src_ip & 0xFFFF0000) == 0xC0A80000) {
            log_info("  Source network: Private (192.168.0.0/16)");
          } else if (src_ip == 0x7F000001) {
            log_info("  Source network: Localhost (127.0.0.1)");
          } else {
            log_info("  Source network: Public/external");
          }
        }
      }
    }
    if (arg2 != 0 && arg3 >= 8) {
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, arg2, 0, &family) == VMI_SUCCESS) {
        if (family == AF_INET) {
          uint16_t port = 0;
          uint32_t ip_addr = 0;
          if (vmi_read_16_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_PORT_OFFSET, 0,
                             &port) == VMI_SUCCESS &&
              vmi_read_32_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_ADDR_OFFSET, 0,
                             &ip_addr) == VMI_SUCCESS) {
            struct in_addr addr = {.s_addr = ip_addr};
            uint16_t host_port = ntohs(port);

            log_info("  Destination: %s:%u", inet_ntoa(addr), host_port);

            if (host_port < 1024) {  // Well-known ports (0-1023) - IANA
              log_info("  Port %u: Well-known port (privileged)", host_port);
              // Registered ports (1024-49151) - IANA
            } else if (host_port >= 1024 && host_port < 49152) {
              log_info("  Port %u: Registered port", host_port);
              // Dynamic/private ports (49152-65535) - RFC 6335
            } else if (host_port >= 49152) {
              log_info("  Port %u: Dynamic/private port", host_port);
            }

            if ((ip_addr & 0xFF000000) == 0x0A000000) {  // 10.0.0.0/8
              log_info("  Destination network: Private (10.0.0.0/8)");
            } else if ((ip_addr & 0xFFF00000) == 0xAC100000) {  // 172.16.0.0/12
              log_info("  Destination network: Private (172.16.0.0/12)");
            } else if ((ip_addr & 0xFFFF0000) ==
                       0xC0A80000) {  // 192.168.0.0/16
              log_info("  Destination network: Private (192.168.0.0/16)");
            } else if (ip_addr == 0x7F000001) {  // 127.0.0.1
              log_info("  Destination network: Localhost (127.0.0.1)");
            } else {
              log_info("  Destination network: Public/external");
            }
          }
        } else if (family == AF_INET6) {
          log_info("  IPv6 connection detected (family: %u)", family);
        }
      }
    }
  } else if (strstr(func_name, "tcp_accept")) {

    log_info("INTERRUPT_NETWORK_MONITOR: tcp_accept() called - TCP accept");
    log_info("  Socket: 0x%" PRIx64 ", Flags: %" PRIu64, arg1, arg2);
    log_info("  Function: Accepts incoming TCP connection");

    if (arg1 != 0) {
      addr_t skc_addr = (addr_t)arg1;

      uint16_t listen_port = 0;
      if (vmi_read_16_va(vmi, skc_addr + LINUX_SKC_NUM_OFFSET, 0,
                         &listen_port) == VMI_SUCCESS) {
        uint16_t host_listen_port = ntohs(listen_port);

        uint32_t listen_ip = 0;
        if (vmi_read_32_va(vmi, skc_addr + LINUX_SKC_RCV_SADDR_OFFSET, 0,
                           &listen_ip) == VMI_SUCCESS) {
          struct in_addr listen_addr = {.s_addr = listen_ip};

          log_info("  Listening on: %s:%u", inet_ntoa(listen_addr),
                   host_listen_port);

          if (host_listen_port < 1024) {
            log_info("  Port %u: Privileged port (requires root privileges)",
                     host_listen_port);
          } else if (host_listen_port >= 1024 && host_listen_port < 49152) {
            log_info("  Port %u: Registered port range", host_listen_port);
          } else if (host_listen_port >= 49152) {
            log_info("  Port %u: Dynamic/private port range", host_listen_port);
          }
        }
      }
    }

    // SOCK_NONBLOCK - see include/uapi/linux/net.h
    if (arg2 & 0x800) {
      log_info("  Flag: SOCK_NONBLOCK (non-blocking operation)");
    }
    // SOCK_CLOEXEC - see include/uapi/linux/net.h
    if (arg2 & 0x80000) {
      log_info("  Flag: SOCK_CLOEXEC (close on exec)");
    }
    if (arg2 == 0) {
      log_info("  Flags: None (blocking operation)");
    }
  } else if (strstr(func_name, "tcp_close")) {

    log_info(
        "INTERRUPT_NETWORK_MONITOR: tcp_close() called - TCP connection "
        "closure");
    log_info("  Socket: 0x%" PRIx64 ", Timeout: %" PRIu64, arg1, arg2);
    log_info("  Function: Closes TCP connection with graceful shutdown");

    if (arg1 != 0) {
      addr_t skc_addr = (addr_t)arg1;

      uint16_t src_port = 0;
      if (vmi_read_16_va(vmi, skc_addr + LINUX_SKC_NUM_OFFSET, 0, &src_port) ==
          VMI_SUCCESS) {
        uint16_t host_src_port = ntohs(src_port);

        uint16_t dst_port = 0;
        if (vmi_read_16_va(vmi, skc_addr + LINUX_SKC_DPORT_OFFSET, 0,
                           &dst_port) == VMI_SUCCESS) {
          uint16_t host_dst_port = ntohs(dst_port);

          uint32_t src_ip = 0;
          if (vmi_read_32_va(vmi, skc_addr + LINUX_SKC_RCV_SADDR_OFFSET, 0,
                             &src_ip) == VMI_SUCCESS) {
            struct in_addr src_addr = {.s_addr = src_ip};

            uint32_t dst_ip = 0;
            if (vmi_read_32_va(vmi, skc_addr + LINUX_SKC_DADDR_OFFSET, 0,
                               &dst_ip) == VMI_SUCCESS) {
              struct in_addr dst_addr = {.s_addr = dst_ip};

              log_info("  Connection: %s:%u -> %s:%u", inet_ntoa(src_addr),
                       host_src_port, inet_ntoa(dst_addr), host_dst_port);

              if ((src_ip & 0xFF000000) == 0x0A000000 ||
                  (src_ip & 0xFFF00000) == 0xAC100000 ||
                  (src_ip & 0xFFFF0000) == 0xC0A80000) {
                log_info("  Source: Private network");
              } else {
                log_info("  Source: Public network");
              }

              if ((dst_ip & 0xFF000000) == 0x0A000000 ||
                  (dst_ip & 0xFFF00000) == 0xAC100000 ||
                  (dst_ip & 0xFFFF0000) == 0xC0A80000) {
                log_info("  Destination: Private network");
              } else {
                log_info("  Destination: Public network");
              }
            }
          }
        }
      }
    }

    if (arg2 == 0) {
      log_info("  Timeout: 0 (immediate close)");
    } else if (arg2 < 100) {
      log_info("  Timeout: %" PRIu64 " jiffies (short timeout)", arg2);
    } else if (arg2 < 1000) {
      log_info("  Timeout: %" PRIu64 " jiffies (moderate timeout)", arg2);
    } else {
      log_info("  Timeout: %" PRIu64 " jiffies (long timeout)", arg2);
    }
  } else if (strstr(func_name, "tcp_shutdown")) {

    log_info(
        "INTERRUPT_NETWORK_MONITOR: tcp_shutdown() called - TCP connection "
        "shutdown");
    log_info("  Socket: 0x%" PRIx64 ", How: %" PRIu64, arg1, arg2);
    log_info("  Function: Shuts down TCP connection in specified direction");

    if (arg1 != 0) {
      addr_t skc_addr = (addr_t)arg1;

      uint16_t src_port = 0;
      if (vmi_read_16_va(vmi, skc_addr + LINUX_SKC_NUM_OFFSET, 0, &src_port) ==
          VMI_SUCCESS) {
        uint16_t host_src_port = ntohs(src_port);

        uint16_t dst_port = 0;
        if (vmi_read_16_va(vmi, skc_addr + LINUX_SKC_DPORT_OFFSET, 0,
                           &dst_port) == VMI_SUCCESS) {
          uint16_t host_dst_port = ntohs(dst_port);

          uint32_t src_ip = 0;
          if (vmi_read_32_va(vmi, skc_addr + LINUX_SKC_RCV_SADDR_OFFSET, 0,
                             &src_ip) == VMI_SUCCESS) {
            struct in_addr src_addr = {.s_addr = src_ip};

            uint32_t dst_ip = 0;
            if (vmi_read_32_va(vmi, skc_addr + LINUX_SKC_DADDR_OFFSET, 0,
                               &dst_ip) == VMI_SUCCESS) {
              struct in_addr dst_addr = {.s_addr = dst_ip};

              log_info("  Connection: %s:%u -> %s:%u", inet_ntoa(src_addr),
                       host_src_port, inet_ntoa(dst_addr), host_dst_port);
            }
          }
        }
      }
    }

    if (arg2 == 0) {  // SHUT_RD - see include/uapi/linux/net.h
      log_info("  Shutdown: SHUT_RD (close read side)");
    } else if (arg2 == 1) {  // SHUT_WR - see include/uapi/linux/net.h
      log_info("  Shutdown: SHUT_WR (close write side)");
    } else if (arg2 == 2) {  // SHUT_RDWR - see include/uapi/linux/net.h
      log_info("  Shutdown: SHUT_RDWR (close both sides)");
    } else {
      log_info("  Shutdown: Unknown direction (%" PRIu64 ")", arg2);
    }
  } else if (strstr(func_name, "udp_bind")) {

    log_info("INTERRUPT_NETWORK_MONITOR: udp_bind() called - UDP binding");
    log_info("  Socket: 0x%" PRIx64 ", Address: 0x%" PRIx64
             ", Length: %" PRIu64,
             arg1, arg2, arg3);
    log_info("  Function: Binds UDP socket to specific address and port");

    if (arg2 != 0 && arg3 >= 2) {
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, arg2, 0, &family) == VMI_SUCCESS) {
        if (family == AF_INET &&
            arg3 >= 8) {  // IPv4 sockaddr_in - see include/uapi/linux/in.h
          uint16_t port = 0;
          uint32_t ip_addr = 0;
          if (vmi_read_16_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_PORT_OFFSET, 0,
                             &port) == VMI_SUCCESS &&
              vmi_read_32_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_ADDR_OFFSET, 0,
                             &ip_addr) == VMI_SUCCESS) {
            struct in_addr addr = {.s_addr = ip_addr};
            uint16_t host_port = ntohs(port);

            log_info("  Binding to: %s:%u", inet_ntoa(addr), host_port);

            if (host_port < 1024) {  // Well-known ports (0-1023) - IANA
              log_info("  Port %u: Well-known port (privileged)", host_port);
              // Registered ports (1024-49151) - IANA
            } else if (host_port >= 1024 && host_port < 49152) {
              log_info("  Port %u: Registered port", host_port);
              // Dynamic/private ports (49152-65535) - RFC 6335
            } else if (host_port >= 49152) {
              log_info("  Port %u: Dynamic/private port", host_port);
            }

            if (ip_addr == 0) {
              log_info(
                  "  IP: INADDR_ANY (0.0.0.0) - binding to all interfaces");
            } else if (ip_addr == 0x7F000001) {  // 127.0.0.1
              log_info("  IP: Localhost (127.0.0.1) - loopback only");
            } else if ((ip_addr & 0xFF000000) ==
                       0x0A000000) {  // 10.0.0.0/8 - RFC 1918
              log_info("  IP: Private network (10.0.0.0/8)");
            } else if ((ip_addr & 0xFFF00000) ==
                       0xAC100000) {  // 172.16.0.0/12 - RFC 1918
              log_info("  IP: Private network (172.16.0.0/12)");
            } else if ((ip_addr & 0xFFFF0000) ==
                       0xC0A80000) {  // 192.168.0.0/16 - RFC 1918
              log_info("  IP: Private network (192.168.0.0/16)");
            } else {
              log_info("  IP: Public/external address");
            }
          }
        } else if (
            family == AF_INET6 &&
            arg3 >= 28) {  // IPv6 sockaddr_in6 - see include/uapi/linux/in6.h
          log_info("  IPv6 UDP binding detected (family: %u)", family);
        }
      }
    }
  } else if (strstr(func_name, "udp_connect")) {

    log_info("INTERRUPT_NETWORK_MONITOR: udp_connect() called - UDP connect");
    log_info("  Socket: 0x%" PRIx64 ", Address: 0x%" PRIx64
             ", Length: %" PRIu64,
             arg1, arg2, arg3);
    log_info("  Function: Sets default destination for UDP socket");

    if (arg2 != 0 && arg3 >= 8) {
      uint16_t family = 0;
      if (vmi_read_16_va(vmi, arg2, 0, &family) == VMI_SUCCESS) {
        if (family == AF_INET) {
          uint16_t port = 0;
          uint32_t ip_addr = 0;
          if (vmi_read_16_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_PORT_OFFSET, 0,
                             &port) == VMI_SUCCESS &&
              vmi_read_32_va(vmi, arg2 + LINUX_SOCKADDR_IN_SIN_ADDR_OFFSET, 0,
                             &ip_addr) == VMI_SUCCESS) {
            struct in_addr addr = {.s_addr = ip_addr};
            uint16_t host_port = ntohs(port);

            log_info("  Default destination: %s:%u", inet_ntoa(addr),
                     host_port);

            if (host_port < 1024) {  // Well-known ports (0-1023) - IANA
              log_info("  Port %u: Well-known port", host_port);
              // Registered ports (1024-49151) - IANA
            } else if (host_port >= 1024 && host_port < 49152) {
              log_info("  Port %u: Registered port", host_port);
              // Dynamic/private ports (49152-65535) - RFC 6335
            } else if (host_port >= 49152) {
              log_info("  Port %u: Dynamic/private port", host_port);
            }

            if ((ip_addr & 0xFF000000) == 0x0A000000) {  // 10.0.0.0/8
              log_info("  Destination: Private network (10.0.0.0/8)");
            } else if ((ip_addr & 0xFFF00000) == 0xAC100000) {  // 172.16.0.0/12
              log_info("  Destination: Private network (172.16.0.0/12)");
            } else if ((ip_addr & 0xFFFF0000) ==
                       0xC0A80000) {  // 192.168.0.0/16
              log_info("  Destination: Private network (192.168.0.0/16)");
            } else if (ip_addr == 0x7F000001) {  // 127.0.0.1
              log_info("  Destination: Localhost (127.0.0.1)");
            } else {
              log_info("  Destination: Public/external network");
            }
          }
        } else if (family == AF_INET6) {
          log_info("  IPv6 UDP connect detected (family: %u)", family);
        }
      }
    }
  } else if (strstr(func_name, "udp_disconnect")) {

    log_info(
        "INTERRUPT_NETWORK_MONITOR: udp_disconnect() called - UDP disconnect");
    log_info("  Socket: 0x%" PRIx64 ", Flags: %" PRIu64, arg1, arg2);
    log_info("  Function: Removes default destination from UDP socket");

    if (arg1 != 0) {
      addr_t skc_addr = (addr_t)arg1;

      uint16_t src_port = 0;
      if (vmi_read_16_va(vmi, skc_addr + LINUX_SKC_NUM_OFFSET, 0, &src_port) ==
          VMI_SUCCESS) {
        uint16_t host_src_port = ntohs(src_port);

        uint32_t src_ip = 0;
        if (vmi_read_32_va(vmi, skc_addr + LINUX_SKC_RCV_SADDR_OFFSET, 0,
                           &src_ip) == VMI_SUCCESS) {
          struct in_addr src_addr = {.s_addr = src_ip};

          log_info("  UDP socket: %s:%u", inet_ntoa(src_addr), host_src_port);
        }
      }
    }
  } else if (strstr(func_name, "nf_register_net_hook")) {
    log_info("NETFILTER: Hook registration detected");
    log_info("  Network namespace: 0x%" PRIx64 ", Hook operations: 0x%" PRIx64,
             arg1, arg2);

    if (arg2 != 0) {
      uint32_t hook_position = 0;
      uint8_t protocol_family = 0;

      if (vmi_read_32_va(vmi, arg2 + LINUX_NF_HOOK_OPS_HOOKNUM_OFFSET, 0,
                         &hook_position) == VMI_SUCCESS &&
          vmi_read_8_va(vmi, arg2 + LINUX_NF_HOOK_OPS_PF_OFFSET, 0,
                        &protocol_family) == VMI_SUCCESS) {

        // Netfilter hook positions - see include/uapi/linux/netfilter.h
        const char* hook_positions[] = {
            "PRE_ROUTING",  // Before routing decision
            "LOCAL_IN",     // Incoming to local process
            "FORWARD",      // Forwarded packets
            "LOCAL_OUT",    // Outgoing from local process
            "POST_ROUTING"  // After routing decision
        };

        // Protocol families - see include/uapi/linux/netfilter.h
        const char* protocol_families[] = {
            "UNSPECIFIED", "INET", "IPv4",   "ARP",          "NETDEV",
            "BRIDGE",      "IPv6", "DECNET", "NUM_PROTOCOLS"};

        const char* hook_name =
            (hook_position < 5) ? hook_positions[hook_position] : "UNKNOWN";
        const char* protocol_name = (protocol_family < 9)
                                        ? protocol_families[protocol_family]
                                        : "UNKNOWN";

        log_info("  Hook Position: %s, Protocol Family: %s", hook_name,
                 protocol_name);
      }
    }
  } else if (strstr(func_name, "nf_unregister_net_hook")) {
    log_info("NETFILTER: Hook unregistration detected");
    log_info("  Network namespace: 0x%" PRIx64 ", Hook operations: 0x%" PRIx64,
             arg1, arg2);
  } else if (strstr(func_name, "dev_open")) {
    log_info(
        "INTERRUPT_NETWORK_MONITOR: dev_open() called - Network device "
        "opening");
    log_info("  Device: 0x%" PRIx64, arg1);
  } else if (strstr(func_name, "dev_close")) {
    log_info(
        "INTERRUPT_NETWORK_MONITOR: dev_close() called - Network device "
        "closing");
    log_info("  Device: 0x%" PRIx64, arg1);
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

  if (vmi_get_vcpureg(vmi, &rip, RIP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to get RIP register value.");
  }

  if (vmi_get_vcpureg(vmi, &cr3, CR3, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to get CR3 register value.");
  }

  if (vmi_get_vcpureg(vmi, &rsp, RSP, vcpu_id) != VMI_SUCCESS) {
    return log_error_and_queue_response_interrupt(
        "network_monitor", INTERRUPT_NETWORK_MONITOR, VMI_OP_FAILURE,
        "Failed to get RSP register value.");
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

  // Log comprehensive execution context
  log_info("Timestamp: %ld", time(NULL));
  log_info("Function: %s @ 0x%" PRIx64, func_name, ctx->kaddr);
  log_info("vCPU: %u, RIP: 0x%" PRIx64 ", RSP: 0x%" PRIx64 ", CR3: 0x%" PRIx64,
           vcpu_id, rip, rsp, cr3);
  log_info("Registers: RDI=0x%" PRIx64 " RSI=0x%" PRIx64 " RDX=0x%" PRIx64
           " RCX=0x%" PRIx64 " R8=0x%" PRIx64 " R9=0x%" PRIx64,
           rdi, rsi, rdx, rcx, r8, r9);

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

  log_warn(
      "Network function call detected - potential network activity monitoring");

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