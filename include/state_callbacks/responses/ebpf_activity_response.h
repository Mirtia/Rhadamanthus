/**
 * @file ebpf_activity_response.h
 * @brief Response structure and functions for eBPF activity state analysis.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef EBPF_ACTIVITY_RESPONSE_H
#define EBPF_ACTIVITY_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (ebpf_activity_state_response)
 * ─────────────────────────────────────────────
 * {
 *   "state": "EBPF_ACTIVITY",
 *   "loaded_programs": [
 *     {
 *       "id": 12,
 *       "type": "kprobe",
 *       "name": "handle_sched",
 *       "attach_type": "kprobe",
 *       "prog_addr": "0xffffffffc0000000",
 *       "aux_addr": "0xffffffffc0001000",
 *       "pid": 1234,
 *       "process_name": "nginx"
 *     }
 *   ],
 *   "attachment_points": {
 *     "kprobe": [12, 37],
 *     "tracepoint": [45, 67]
 *   },
 *   "summary": {
 *     "total_programs": 5,
 *     "total_maps": 3,
 *     "total_links": 2,
 *     "total_btf_objects": 1,
 *     "processes_with_ebpf": 2,
 *     "programs_by_type": {
 *       "kprobe": 3,
 *       "tracepoint": 2
 *     }
 *   }
 * }
 */

/**
 * @brief Information about an eBPF program.
 */
typedef struct ebpf_program_info {
  uint32_t id;         ///< Program ID
  char* type;          ///< Program type (kprobe, tracepoint, etc.)
  char* name;          ///< Program name
  char* attach_type;   ///< Attachment type
  uint64_t prog_addr;  ///< Program address
  uint64_t aux_addr;   ///< Auxiliary data address
  uint32_t pid;        ///< Process ID that owns this program
  char* process_name;  ///< Process name that owns this program
} ebpf_program_info_t;

/**
 * @brief Information about eBPF maps.
 */
typedef struct ebpf_map_info {
  uint32_t id;         ///< Map ID
  uint64_t map_addr;   ///< Map address
  uint32_t pid;        ///< Process ID that owns this map
  char* process_name;  ///< Process name that owns this map
} ebpf_map_info_t;

/**
 * @brief Information about eBPF links.
 */
typedef struct ebpf_link_info {
  uint32_t id;         ///< Link ID
  uint64_t link_addr;  ///< Link address
  uint32_t pid;        ///< Process ID that owns this link
  char* process_name;  ///< Process name that owns this link
} ebpf_link_info_t;

/**
 * @brief Summary information for eBPF activity analysis.
 */
typedef struct ebpf_activity_summary {
  uint32_t total_programs;       ///< Total number of eBPF programs
  uint32_t total_maps;           ///< Total number of eBPF maps
  uint32_t total_links;          ///< Total number of eBPF links
  uint32_t total_btf_objects;    ///< Total number of BTF objects
  uint32_t processes_with_ebpf;  ///< Number of processes using eBPF
  GHashTable* programs_by_type;  ///< Hash table of program counts by type
} ebpf_activity_summary_t;

/**
 * @brief State data for eBPF activity analysis.
 */
typedef struct ebpf_activity_state_data {
  GArray* loaded_programs;          ///< Array of ebpf_program_info_t
  GArray* maps;                     ///< Array of ebpf_map_info_t
  GArray* links;                    ///< Array of ebpf_link_info_t
  GHashTable* attachment_points;    ///< Hash table of attachment points by type
  ebpf_activity_summary_t summary;  ///< Summary information
} ebpf_activity_state_data_t;

/**
 * @brief Allocate and initialize a new eBPF activity state data object.
 *
 * @return Pointer to a newly allocated ebpf_activity_state_data_t, or NULL on failure.
 */
ebpf_activity_state_data_t* ebpf_activity_state_data_new(void);

/**
 * @brief Free an eBPF activity state data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void ebpf_activity_state_data_free(ebpf_activity_state_data_t* data);

/**
 * @brief Add an eBPF program to the list.
 *
 * @param data The eBPF activity state data object.
 * @param id Program ID.
 * @param type Program type.
 * @param name Program name.
 * @param attach_type Attachment type.
 * @param prog_addr Program address.
 * @param aux_addr Auxiliary data address.
 * @param pid Process ID.
 * @param process_name Process name.
 */
void ebpf_activity_state_add_program(ebpf_activity_state_data_t* data,
                                     uint32_t id, const char* type,
                                     const char* name, const char* attach_type,
                                     uint64_t prog_addr, uint64_t aux_addr,
                                     uint32_t pid, const char* process_name);

/**
 * @brief Add an eBPF map to the list.
 *
 * @param data The eBPF activity state data object.
 * @param id Map ID.
 * @param map_addr Map address.
 * @param pid Process ID.
 * @param process_name Process name.
 */
void ebpf_activity_state_add_map(ebpf_activity_state_data_t* data, uint32_t id,
                                 uint64_t map_addr, uint32_t pid,
                                 const char* process_name);

/**
 * @brief Add an eBPF link to the list.
 *
 * @param data The eBPF activity state data object.
 * @param id Link ID.
 * @param link_addr Link address.
 * @param pid Process ID.
 * @param process_name Process name.
 */
void ebpf_activity_state_add_link(ebpf_activity_state_data_t* data, uint32_t id,
                                  uint64_t link_addr, uint32_t pid,
                                  const char* process_name);

/**
 * @brief Add an attachment point to the attachment points hash table.
 *
 * @param data The eBPF activity state data object.
 * @param attach_type Attachment type.
 * @param program_id Program ID to add.
 */
void ebpf_activity_state_add_attachment_point(ebpf_activity_state_data_t* data,
                                              const char* attach_type,
                                              uint32_t program_id);

/**
 * @brief Set the summary information.
 *
 * @param data The eBPF activity state data object.
 * @param total_programs Total number of programs.
 * @param total_maps Total number of maps.
 * @param total_links Total number of links.
 * @param total_btf_objects Total number of BTF objects.
 * @param processes_with_ebpf Number of processes using eBPF.
 */
void ebpf_activity_state_set_summary(ebpf_activity_state_data_t* data,
                                     uint32_t total_programs,
                                     uint32_t total_maps, uint32_t total_links,
                                     uint32_t total_btf_objects,
                                     uint32_t processes_with_ebpf);

/**
 * @brief Serialize an eBPF activity state data object to JSON.
 *
 * @param data Pointer to the eBPF activity state data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* ebpf_activity_state_data_to_json(const ebpf_activity_state_data_t* data);

#endif  // EBPF_ACTIVITY_RESPONSE_H
