// process_relationship.h

#ifndef PROCESS_RELATIONSHIP_H
#define PROCESS_RELATIONSHIP_H

#include <stdbool.h>
#include <sys/types.h>
#include <limits.h>

typedef struct {
    pid_t pid;
    pid_t ppid;
    char exec_path[PATH_MAX];
    char cmd_line[PATH_MAX];
    bool suspicious;
} process_info_t;

/**
 * Initialize the process relationship analyzer
 * @return true on success, false on failure
 */
bool init_process_relationship(void);

/**
 * Analyze process relationships to find suspicious processes
 * @param target_pid Specific PID to analyze, or -1 to analyze all processes
 * @param results Array to store suspicious process information
 * @param max_results Maximum number of results to return
 * @return Number of suspicious processes found
 */
int analyze_process_relationships(pid_t target_pid, process_info_t *results, int max_results);

void cleanup_process_relationship(void);

#endif 