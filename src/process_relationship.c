// process_relationship.c

#include "process_relationship.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>

#define MAX_PROCESSES 1024
#define MAX_SUSPICIOUS_PATHS 16

static const char *suspicious_paths[] = {
    "/tmp/", 
    "/dev/shm/", 
    "/run/user/",
    "/var/tmp/",
    NULL
};

// Process information cache
static process_info_t process_cache[MAX_PROCESSES];
static int process_count = 0;

// Read process information from /proc
static bool read_process_info(pid_t pid, process_info_t *info) {
    char path[PATH_MAX];
    char buffer[PATH_MAX];
    FILE *file;
    
    info->pid = pid;
    info->ppid = 0;
    info->exec_path[0] = '\0';
    info->cmd_line[0] = '\0';
    info->suspicious = false;
    
    snprintf(path, PATH_MAX, "/proc/%d/exe", pid);
    ssize_t len = readlink(path, buffer, PATH_MAX - 1);
    if (len > 0) {
        buffer[len] = '\0';
        strncpy(info->exec_path, buffer, PATH_MAX - 1);
        info->exec_path[PATH_MAX - 1] = '\0';
    } else {
        return false;
    }
    
    snprintf(path, PATH_MAX, "/proc/%d/cmdline", pid);
    file = fopen(path, "r");
    if (file) {
        size_t bytes = fread(buffer, 1, PATH_MAX - 1, file);
        fclose(file);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            for (size_t i = 0; i < bytes; i++) {
                if (buffer[i] == '\0') {
                    buffer[i] = ' ';
                }
            }
            strncpy(info->cmd_line, buffer, PATH_MAX - 1);
            info->cmd_line[PATH_MAX - 1] = '\0';
        }
    }
    
    snprintf(path, PATH_MAX, "/proc/%d/stat", pid);
    file = fopen(path, "r");
    if (file) {
        if (fscanf(file, "%*d %*s %*c %d", &info->ppid) == 1) {
            fclose(file);
        } else {
            fclose(file);
            return false;
        }
    } else {
        return false;
    }
    
    for (int i = 0; suspicious_paths[i] != NULL; i++) {
        if (strncmp(info->exec_path, suspicious_paths[i], 
                   strlen(suspicious_paths[i])) == 0) {
            info->suspicious = true;
            break;
        }
    }
    
    return true;
}

bool init_process_relationship(void) {
    process_count = 0;
    return true;
}

int analyze_process_relationships(pid_t target_pid, process_info_t *results, int max_results) {
    if (results == NULL || max_results <= 0) {
        return 0;
    }    
    memset(results, 0, sizeof(process_info_t) * max_results);
    
    if (target_pid > 0) {
        process_info_t info;
        if (read_process_info(target_pid, &info)) {
            memcpy(&results[0], &info, sizeof(process_info_t));
            return 1;
        }
        return 0;
    }
    
    // Refresh process cache
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        return 0;
    }
    
    process_count = 0;
    struct dirent *entry;
    
    // First pass
    while ((entry = readdir(proc_dir)) != NULL && process_count < MAX_PROCESSES) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') {
            continue;
        }
        
        pid_t pid = atoi(entry->d_name);
        if (pid > 0) {
            if (read_process_info(pid, &process_cache[process_count])) {
                process_count++;
            }
        }
    }
    
    closedir(proc_dir);
    
    // Second pass
    int result_count = 0;
    
    for (int i = 0; i < process_count && result_count < max_results; i++) {
        process_info_t *proc = &process_cache[i];
        
        // Skip kernel processes
        if (proc->ppid <= 1) {
            continue;
        }
        
        if (proc->suspicious) {
            memcpy(&results[result_count++], proc, sizeof(process_info_t));
            continue;
        }
        
        for (int j = 0; j < process_count; j++) {
            if (process_cache[j].pid == proc->ppid) {
                if (process_cache[j].suspicious && !proc->suspicious) {
                    memcpy(&results[result_count++], proc, sizeof(process_info_t));
                    break;
                }
            }
        }
    }
    
    return result_count;
}

void cleanup_process_relationship(void) {
    process_count = 0;
}