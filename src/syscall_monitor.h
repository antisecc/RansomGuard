// syscall_monitor.h
#ifndef SYSCALL_MONITOR_H
#define SYSCALL_MONITOR_H

#include <stdbool.h>

bool init_syscall_monitor(pid_t target_pid);

void start_syscall_monitoring();
void cleanup_syscall_monitor();

#endif