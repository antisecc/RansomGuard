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

bool init_process_relationship(void);

int analyze_process_relationships(pid_t target_pid, process_info_t *results, int max_results);

bool check_suspicious_parent_child(pid_t parent_pid, pid_t child_pid, 
                                  int *suspicion_score, char *reason_buffer, 
                                  size_t reason_size);

void cleanup_process_relationship(void);

#endif