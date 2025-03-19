// file_monitor.h
#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include <stdbool.h>

extern volatile int keep_running;
bool init_file_monitor(const char *watch_path);
void start_file_monitoring(void);
void cleanup_file_monitor(void);

pid_t get_file_modifier_pid(const char *filename);
bool process_has_file_open(pid_t pid, const char *target_file);
bool has_recent_network_activity(pid_t pid);
bool is_process_suspicious(pid_t pid);
pid_t get_parent_pid(pid_t pid);

bool track_file_modification_frequency(pid_t pid, const char *path, file_op_type_t op_type);

void get_frequency_report(pid_t pid, char *message, size_t message_size);

void reset_file_modification_tracker(pid_t pid);

void init_file_modification_tracker(void);

#endif