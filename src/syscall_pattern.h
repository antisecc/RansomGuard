// syscall_pattern.h
#ifndef SYSCALL_PATTERN_H
#define SYSCALL_PATTERN_H

#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#define SYSCALL_HISTORY_SIZE 50
#define MAX_TRACKED_PROCESSES 64

typedef enum {
    PATTERN_NORMAL = 0,
    PATTERN_SUSPICIOUS,
    PATTERN_RANSOMWARE,
    PATTERN_EVASIVE
} pattern_type_t;

typedef struct {
    pid_t pid;
    pattern_type_t pattern_type;
    int confidence;  
    const char *description;
} syscall_pattern_result_t;

typedef struct {
    int syscall_num;
    unsigned long args[6];
    struct timespec timestamp;
} syscall_record_t;

typedef struct {
    pid_t pid;
    syscall_record_t history[SYSCALL_HISTORY_SIZE];
    int history_index;
    int suspicious_sequences;
} process_syscall_history_t;

/**
 * Initialize syscall pattern analysis
 * @return true on success, false on failure
 */
bool init_syscall_pattern(void);

/**
 * Record a system call for pattern analysis
 * @param pid Process ID
 * @param syscall_nr System call number
 * @param args System call arguments (optional, can be NULL)
 * @param arg_count Number of arguments
 */
void record_syscall(pid_t pid, long syscall_nr, long *args, int arg_count);

/**
 * Analyze recorded syscall patterns for suspicious behavior
 * @param pid Process ID to analyze, or -1 for all processes
 * @param results Array to store results in
 * @param max_results Maximum number of results to return
 * @return Number of suspicious patterns found
 */
int analyze_syscall_patterns(pid_t pid, syscall_pattern_result_t *results, int max_results);

void cleanup_syscall_pattern(void);

#endif 