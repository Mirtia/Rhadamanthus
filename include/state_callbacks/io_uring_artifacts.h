/**
 * @file io_uring_artifacts.h
 * @brief Inspects io_uring artifacts in the kernel.
 * @version 0.0
 * @date 2025-08-24
 * 
 * @copyright GNU Lesser General Public License v2.1
 * 
 */
#ifndef IO_URING_ARTIFACTS_H
#define IO_URING_ARTIFACTS_H

#include <libvmi/libvmi.h>
#include <stdint.h>

/**
 * @brief Enumerate per-task io_uring artifacts. Performs sanity-checks.
 *
 * Iterates the Linux task list (init_task->tasks) using profile offsets
 * (linux_tasks, linux_pid, linux_name). For each task_struct, inspects
 * io_uring state via hardcoded offsets into:
 *   task->io_uring -> last ctx -> rings -> SQ/CQ entries.
 * Logs per-PID results (ctx/rings VAs, SQ/CQ sizes).
 *
 * Offsets for io_uring internals are for v5.15.0-139-generic and MUST be
 * regenerated (e.g., `pahole --hex vmlinux`) if the target kernel changes.
 *
 * @param vmi The VMI instance.
 * @param context User-defined context [unused].
 * @return VMI_SUCCESS on successful inspection, else VMI_FAILURE.
 */
uint32_t state_io_uring_artifacts_callback(vmi_instance_t vmi, void* context);

#endif  // IO_URING_ARTIFACTS_H
