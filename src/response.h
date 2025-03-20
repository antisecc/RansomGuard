// response.h
#ifndef RESPONSE_H
#define RESPONSE_H

#include <stdbool.h>
#include <sys/types.h>

// Log a suspicious activity
void log_suspicious_activity(const char *message);
void response_log_activity(const char *message);
void record_suspicious_activity(const char *message);

// Take action against a suspicious process
bool terminate_process(pid_t pid);

// Protect a file from modification
bool protect_file(const char *filepath);

#endif