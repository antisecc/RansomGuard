// process_analyzer.h
#ifndef PROCESS_ANALYZER_H
#define PROCESS_ANALYZER_H

#include <stdbool.h>
#include <sys/types.h>
#include "common_defs.h"  // For file_op_type_t, risk_level_t 
#include "activity_scorer.h"  // For score_operation_t
#include "behavioral_analysis.h"  // For record_file_operation

#define MAX_PATH 4096

typedef struct {
    pid_t pid;
    bool suspicious;
    pid_t parent_pid;
    int score;
    char binary_path[MAX_PATH];
    char reason[256];  // Add proper size for reason
} process_suspicion_t;

// Initialize the process analyzer
bool init_process_analyzer(pid_t target_pid);

// Analyze process behavior
void analyze_process(void);

// Clean up resources
void cleanup_process_analyzer(void);

// Process a file event
void process_file_event(const char *path, const char *full_path, 
                       file_op_type_t op_type, pid_t pid, double entropy, bool high_frequency);

// Check if location is suspicious
bool is_suspicious_location(const char *path);

// Get parent process information
bool get_parent_info(pid_t pid, pid_t *ppid, char *binary_path, size_t path_size);

// Check if binary is trusted
bool is_trusted_binary(const char *binary_path);

// Evaluate a file modification
process_suspicion_t evaluate_file_modification(pid_t pid, const char *file_path);

// Check if a process is suspicious
bool is_process_suspicious(pid_t pid);

// Check if a process is whitelisted
bool is_process_whitelisted(pid_t pid, const char *path);

// Check if parent-child relationship is suspicious
bool check_suspicious_parent_child(pid_t parent_pid, pid_t child_pid, 
                                 int *score, char *reason_buffer, size_t buffer_size);

// Get executable path of a process
bool get_exe_path(pid_t pid, char *buffer, size_t buffer_size);

#endif /* PROCESS_ANALYZER_H */