/**
 * @file process_list_response.h
 * @brief Response structure and functions for process list state analysis.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef PROCESS_LIST_RESPONSE_H
#define PROCESS_LIST_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (process_list_state_response)
 * ─────────────────────────────────────────────
 * {
 *   "state": "PROCESS_LIST",
 *   "count": 150,
 *   "page_size": 4096,
 *   "processes": [
 *     {
 *       "pid": 1,
 *       "name": "init",
 *       "state": "S",
 *       "rss_pages": 1024,
 *       "rss_bytes": 4194304,
 *       "task_struct_addr": "0xffffffff81e00000",
 *       "is_kernel_thread": false,
 *       "credentials": {
 *         "uid": 0,
 *         "gid": 0,
 *         "euid": 0,
 *         "egid": 0
 *       }
 *     }
 *   ],
 *   "summary": {
 *     "total_processes": 150,
 *     "user_processes": 120,
 *     "kernel_threads": 30
 *   }
 * }
 */

/**
 * @brief Process credentials information.
 */
typedef struct process_credentials {
  uint32_t uid;   ///< User ID
  uint32_t gid;   ///< Group ID
  uint32_t euid;  ///< Effective User ID
  uint32_t egid;  ///< Effective Group ID
} process_credentials_t;

/**
 * @brief Information about a single process.
 */
typedef struct process_info {
  uint32_t pid;               ///< Process ID
  char* name;                 ///< Process name (comm)
  char state;                 ///< Process state character
  uint32_t rss_pages;         ///< Resident Set Size in pages
  uint32_t rss_bytes;         ///< Resident Set Size in bytes
  uint64_t task_struct_addr;  ///< Address of the task_struct
  bool is_kernel_thread;      ///< True if it's a kernel thread
  process_credentials_t
      credentials;  ///< Process credentials (valid only for user processes)
} process_info_t;

/**
 * @brief Summary information for process list.
 */
typedef struct process_list_summary {
  uint32_t total_processes;  ///< Total number of processes
  uint32_t user_processes;   ///< Number of user processes
  uint32_t kernel_threads;   ///< Number of kernel threads
} process_list_summary_t;

/**
 * @brief State data for process list analysis.
 */
typedef struct process_list_state_data {
  uint32_t count;                  ///< Total number of processes
  uint32_t page_size;              ///< System page size
  GArray* processes;               ///< Array of process_info_t
  process_list_summary_t summary;  ///< Summary information
} process_list_state_data_t;

/**
 * @brief Allocate and initialize a new process list state data object.
 *
 * @return Pointer to a newly allocated process_list_state_data_t, or NULL on failure.
 */
process_list_state_data_t* process_list_state_data_new(void);

/**
 * @brief Free a process list state data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void process_list_state_data_free(process_list_state_data_t* data);

/**
 * @brief Set the page size and count.
 *
 * @param data The process list state data object.
 * @param page_size System page size.
 * @param count Total number of processes.
 */
void process_list_state_set_basic_info(process_list_state_data_t* data,
                                       uint32_t page_size, uint32_t count);

/**
 * @brief Add process information.
 *
 * @param data The process list state data object.
 * @param pid Process ID.
 * @param name Process name.
 * @param state Process state character.
 * @param rss_pages RSS in pages.
 * @param rss_bytes RSS in bytes.
 * @param task_struct_addr Address of task_struct.
 * @param is_kernel_thread Whether it's a kernel thread.
 * @param credentials Process credentials (can be NULL for kernel threads).
 */
void process_list_state_add_process(process_list_state_data_t* data,
                                    uint32_t pid, const char* name, char state,
                                    uint32_t rss_pages, uint32_t rss_bytes,
                                    uint64_t task_struct_addr,
                                    bool is_kernel_thread,
                                    const process_credentials_t* credentials);

/**
 * @brief Set the summary information.
 *
 * @param data The process list state data object.
 * @param total_processes Total number of processes.
 * @param user_processes Number of user processes.
 * @param kernel_threads Number of kernel threads.
 */
void process_list_state_set_summary(process_list_state_data_t* data,
                                    uint32_t total_processes,
                                    uint32_t user_processes,
                                    uint32_t kernel_threads);

/**
 * @brief Serialize a process list state data object to JSON.
 *
 * @param data Pointer to the process list state data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* process_list_state_data_to_json(const process_list_state_data_t* data);

#endif  // PROCESS_LIST_RESPONSE_H
