// syscall_filter.h
#ifndef SYSCALL_FILTER_H
#define SYSCALL_FILTER_H

#include <stdbool.h>
#include <sys/types.h>

bool init_syscall_filter();

bool apply_restrictive_policy();

void init_memory_protection_tracking(void);

bool filter_syscall(pid_t pid, bool block_suspicious);

struct memory_protection_tracker_t* find_memory_tracker(pid_t pid);

#endif 