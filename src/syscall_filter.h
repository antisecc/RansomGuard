// syscall_filter.h
#ifndef SYSCALL_FILTER_H
#define SYSCALL_FILTER_H

#include <stdbool.h>
#include <sys/types.h>

/**
 * Initialize the syscall filter
 * @return true on success, false on failure
 */
bool init_syscall_filter(void);

/**
 * Apply a restrictive policy
 * @return true on success, false on failure
 */
bool apply_restrictive_policy(void);

/**
 * Setup seccomp filter for a process
 * @return true on success, false on failure
 */
bool setup_seccomp_filter(void);

/**
 * Filter syscalls for a specific process
 * 
 * @param pid Process ID to monitor (0 for self)
 * @param block_suspicious Whether to block the process if suspicious syscalls are detected
 * @return true on success, false on failure
 */
bool filter_syscall(pid_t pid, bool block_suspicious);

/**
 * Clean up syscall filter resources
 */
void cleanup_syscall_filter(void);

#endif /* SYSCALL_FILTER_H */