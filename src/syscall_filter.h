// syscall_filter.h
#ifndef SYSCALL_FILTER_H
#define SYSCALL_FILTER_H

#include <stdbool.h>
#include <sys/types.h>

bool init_syscall_filter();

bool apply_restrictive_policy();

#endif