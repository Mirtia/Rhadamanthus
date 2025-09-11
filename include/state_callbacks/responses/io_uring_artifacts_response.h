/**
 * @file io_uring_artifacts_response.h
 * @brief Response structure and functions for io_uring artifacts state analysis.
 * @version 0.0
 * @date 2025-01-27
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef IO_URING_ARTIFACTS_RESPONSE_H
#define IO_URING_ARTIFACTS_RESPONSE_H

#include <cjson/cJSON.h>
#include <glib-2.0/glib.h>
#include <inttypes.h>
#include <stdbool.h>

/**
 * ─────────────────────────────────────────────
 * JSON Response Structure (io_uring_artifacts_state_response)
 * ─────────────────────────────────────────────
 * {
 *   "state": "IO_URING_ARTIFACTS",
 *   "io_uring_instances": [
 *     {
 *       "pid": 1234,
 *       "process_name": "nginx",
 *       "io_uring_task_addr": "0xffffffffc0000000",
 *       "context_addr": "0xffffffffc0001000",
 *       "rings_addr": "0xffffffffc0002000",
 *       "sq_entries": 256,
 *       "cq_entries": 512,
 *       "geometry_sane": true,
 *       "sq_power_of_two": true,
 *       "cq_power_of_two": true,
 *       "is_suspicious": false
 *     }
 *   ],
 *   "worker_threads": {
 *     "iou_worker_count": 2,
 *     "iou_sqp_count": 1
 *   },
 *   "summary": {
 *     "total_instances": 5,
 *     "suspicious_instances": 0,
 *     "total_worker_threads": 3,
 *     "tasks_scanned": 1000
 *   }
 * }
 */

/**
 * @brief Information about an io_uring instance.
 */
typedef struct io_uring_instance_info {
  uint32_t pid;                 ///< Process ID
  char* process_name;           ///< Process name
  uint64_t io_uring_task_addr;  ///< io_uring_task address
  uint64_t context_addr;        ///< io_ring_ctx address
  uint64_t rings_addr;          ///< io_rings address
  uint32_t sq_entries;          ///< Submission queue entries
  uint32_t cq_entries;          ///< Completion queue entries
  bool geometry_sane;           ///< True if SQ/CQ geometry is valid
  bool sq_power_of_two;         ///< True if SQ entries is power of two
  bool cq_power_of_two;         ///< True if CQ entries is power of two
  bool is_suspicious;           ///< True if instance appears suspicious
} io_uring_instance_info_t;

/**
 * @brief Information about io_uring worker threads.
 */
typedef struct io_uring_worker_threads {
  uint64_t iou_worker_count;  ///< Number of iou-wrk* threads
  uint64_t iou_sqp_count;     ///< Number of iou-sqp* threads
} io_uring_worker_threads_t;

/**
 * @brief Summary information for io_uring artifacts analysis.
 */
typedef struct io_uring_artifacts_summary {
  uint32_t total_instances;       ///< Total number of io_uring instances found
  uint32_t suspicious_instances;  ///< Number of suspicious instances
  uint64_t total_worker_threads;  ///< Total number of worker threads
  uint64_t tasks_scanned;         ///< Number of tasks scanned
} io_uring_artifacts_summary_t;

/**
 * @brief State data for io_uring artifacts analysis.
 */
typedef struct io_uring_artifacts_state_data {
  GArray* io_uring_instances;  ///< Array of io_uring_instance_info_t
  io_uring_worker_threads_t worker_threads;  ///< Worker thread information
  io_uring_artifacts_summary_t summary;      ///< Summary information
} io_uring_artifacts_state_data_t;

/**
 * @brief Allocate and initialize a new io_uring artifacts state data object.
 *
 * @return Pointer to a newly allocated io_uring_artifacts_state_data_t, or NULL on failure.
 */
io_uring_artifacts_state_data_t* io_uring_artifacts_state_data_new(void);

/**
 * @brief Free an io_uring artifacts state data object.
 *
 * @param data Pointer to the object to free (may be NULL).
 */
void io_uring_artifacts_state_data_free(io_uring_artifacts_state_data_t* data);

/**
 * @brief Add an io_uring instance to the list.
 *
 * @param data The io_uring artifacts state data object.
 * @param pid Process ID.
 * @param process_name Process name.
 * @param io_uring_task_addr io_uring_task address.
 * @param context_addr io_ring_ctx address.
 * @param rings_addr io_rings address.
 * @param sq_entries Submission queue entries.
 * @param cq_entries Completion queue entries.
 * @param geometry_sane Whether SQ/CQ geometry is valid.
 * @param sq_power_of_two Whether SQ entries is power of two.
 * @param cq_power_of_two Whether CQ entries is power of two.
 * @param is_suspicious Whether the instance appears suspicious.
 */
void io_uring_artifacts_state_add_instance(
    io_uring_artifacts_state_data_t* data, uint32_t pid,
    const char* process_name, uint64_t io_uring_task_addr,
    uint64_t context_addr, uint64_t rings_addr, uint32_t sq_entries,
    uint32_t cq_entries, bool geometry_sane, bool sq_power_of_two,
    bool cq_power_of_two, bool is_suspicious);

/**
 * @brief Set worker thread information.
 *
 * @param data The io_uring artifacts state data object.
 * @param iou_worker_count Number of iou-wrk* threads.
 * @param iou_sqp_count Number of iou-sqp* threads.
 */
void io_uring_artifacts_state_set_worker_threads(
    io_uring_artifacts_state_data_t* data, uint64_t iou_worker_count,
    uint64_t iou_sqp_count);

/**
 * @brief Set the summary information.
 *
 * @param data The io_uring artifacts state data object.
 * @param total_instances Total number of instances.
 * @param suspicious_instances Number of suspicious instances.
 * @param total_worker_threads Total number of worker threads.
 * @param tasks_scanned Number of tasks scanned.
 */
void io_uring_artifacts_state_set_summary(io_uring_artifacts_state_data_t* data,
                                          uint32_t total_instances,
                                          uint32_t suspicious_instances,
                                          uint64_t total_worker_threads,
                                          uint64_t tasks_scanned);

/**
 * @brief Serialize an io_uring artifacts state data object to JSON.
 *
 * @param data Pointer to the io_uring artifacts state data object.
 * @return Newly allocated cJSON object representing the data, or NULL on failure.
 */
cJSON* io_uring_artifacts_state_data_to_json(
    const io_uring_artifacts_state_data_t* data);

#endif  // IO_URING_ARTIFACTS_RESPONSE_H
