// process_relationship.h 

#ifndef PROCESS_RELATIONSHIP_H
#define PROCESS_RELATIONSHIP_H

#include <stdbool.h>
#include <sys/types.h>

#define MAX_PROC_PATH 256
#define MAX_CMDLINE 1024
#define MAX_TRACKED_PROCS 200

typedef struct {
    pid_t pid;
    pid_t ppid;
    char exec_path[MAX_PROC_PATH];
    char cmdline[MAX_CMDLINE];
    char cwd[MAX_PROC_PATH];
    int suspicious_score;
} process_info_t;
bool init_process_relationship_analyzer(void);
void track_process(pid_t pid);
bool is_process_suspicious(pid_t pid);
pid_t get_parent_pid(pid_t pid);
bool is_suspicious_location(const char *path);
bool get_process_cmdline(pid_t pid, char *buffer, size_t size);
bool get_process_exe(pid_t pid, char *buffer, size_t size);
bool get_process_cwd(pid_t pid, char *buffer, size_t size);
bool has_suspicious_ancestry(pid_t pid);
void cleanup_process_relationship_analyzer(void);

#endif 