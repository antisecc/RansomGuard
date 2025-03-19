// process_analyzer.h
#ifndef PROCESS_ANALYZER_H
#define PROCESS_ANALYZER_H

#include <stdbool.h>
#include <sys/types.h>

typdef struct {
    bool suspicious;
    pid_t parent_pid;
    int score;
    char binary_path[4096];
    char reason[256];
} process_suspicion_t;



bool is_suspicious_location(const char *path);
bool get_parent_info(pid_t pid, pid_t *ppid, char *binary_path, size_t path_size);
bool is_trusted_binary(const char *binary_path);
process_suspicion_t evaluate_file_modification(pid_t pid, const char *file_path);
bool init_process_analyzer(pid_t target_pid);
void analyze_process();
void cleanup_process_analyzer();
void process_file_event(const char *path, const char *full_path, file_op_type_t op_type, 
                       pid_t pid, double entropy, bool high_frequency);

#endif