// file_monitor.h
#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include <stdbool.h>
#include <sys/types.h>
#include "common_defs.h"  // Include first for shared definitions

// Function declarations
bool init_file_monitor(const char *watch_path);
void start_file_monitoring(void);
void cleanup_file_monitor(void);

// File modification tracking
bool track_file_modification_frequency(pid_t pid, const char *path, file_op_type_t op_type);
void get_frequency_report(pid_t pid, char *buffer, size_t buffer_size);
void reset_file_modification_tracker(pid_t pid);

// File processing
void file_monitor_process_event(const char *path, file_op_type_t op_type, pid_t pid);

// Process related functions
pid_t get_file_modifier_pid(const char *filename);
bool process_has_file_open(pid_t pid, const char *target_file);
bool has_recent_network_activity(pid_t pid);
pid_t get_parent_pid(pid_t pid);
bool is_process_suspicious(pid_t pid);

// Threshold management
int check_and_update_threshold(void);

// Scoring related
void prepare_scoring_factors(scoring_factors_t *factors, const char *path, 
                            file_op_type_t op_type, pid_t pid, double entropy, bool high_frequency);

// External functions
extern int calculate_score(pid_t pid, scoring_factors_t *factors);

// External global variable
extern volatile int keep_running;

#endif /* FILE_MONITOR_H */