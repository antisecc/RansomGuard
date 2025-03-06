// daemon_utils.h
#ifndef DAEMON_UTILS_H
#define DAEMON_UTILS_H

#include <stdbool.h>

// Daemonize the current process
bool daemonize();

// Write PID to file
bool write_pid_file(const char *pid_file);

// Remove PID file
void remove_pid_file(const char *pid_file);

#endif