// process_analyzer.c
#include "process_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>

static pid_t target_pid = -1;
static int file_access_count = 0;
static int unique_files_opened = 0;

#define MAX_PATH 4096
#define SUSPICIOUS_FILE_ACCESS_THRESHOLD 50

bool init_process_analyzer(pid_t pid) {
    target_pid = pid;
    
    // Check if the process exists
    char proc_path[MAX_PATH];
    snprintf(proc_path, MAX_PATH, "/proc/%d", target_pid);
    
    DIR *dir = opendir(proc_path);
    if (dir == NULL) {
        perror("Failed to open proc directory");
        return false;
    }
    closedir(dir);
    
    return true;
}

// Track files accessed by the process
static void analyze_open_files() {
    char fd_path[MAX_PATH];
    snprintf(fd_path, MAX_PATH, "/proc/%d/fd", target_pid);
    
    DIR *dir = opendir(fd_path);
    if (dir == NULL) {
        // Could be permission issues or process termination
        return;
    }
    
    int count = 0;
    struct dirent *entry;
    char target_path[MAX_PATH];
    char link_target[MAX_PATH];
    
    // Count and analyze all file descriptors
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;  // Skip . and .. entries
        }
        
        snprintf(target_path, MAX_PATH, "%s/%s", fd_path, entry->d_name);
        
        ssize_t len = readlink(target_path, link_target, MAX_PATH-1);
        if (len != -1) {
            link_target[len] = '\0';
            
            // Skip pseudo-files like socket, pipe, etc.
            if (strncmp(link_target, "socket:", 7) &&
                strncmp(link_target, "pipe:", 5) &&
                strncmp(link_target, "anon_inode:", 11)) {
                count++;
                printf("PID %d has open file: %s\n", target_pid, link_target);
            }
        }
    }
    
    closedir(dir);
    
    // Update counters
    file_access_count += count;
    unique_files_opened += count;
    
    if (file_access_count > SUSPICIOUS_FILE_ACCESS_THRESHOLD) {
        printf("[ALERT] Process %d accessing high number of files: %d\n", 
                target_pid, file_access_count);
        file_access_count = 0;  // Reset counter
    }
}

// Analyze CPU and memory usage
static void analyze_resource_usage() {
    char stat_path[MAX_PATH];
    snprintf(stat_path, MAX_PATH, "/proc/%d/stat", target_pid);
    
    FILE *stat_file = fopen(stat_path, "r");
    if (!stat_file) {
        return;
    }
    
    // Parse relevant process stats
    // Format described in man 5 proc
    char comm[256];
    char state;
    int ppid;
    unsigned long utime, stime;
    
    fscanf(stat_file, "%*d %s %c %d %*d %*d %*d %*d %*u %*lu %*lu %*lu %*lu %lu %lu",
           comm, &state, &ppid, &utime, &stime);
    
    printf("Process %d: state=%c, cpu_time=%lu\n", target_pid, state, utime+stime);
    
    fclose(stat_file);
}

void analyze_process() {
    if (target_pid <= 0) {
        return;
    }
    
    // Check if process still exists
    char proc_path[MAX_PATH];
    snprintf(proc_path, MAX_PATH, "/proc/%d", target_pid);
    
    if (access(proc_path, F_OK) != 0) {
        printf("Process %d no longer exists\n", target_pid);
        return;
    }
    
    // Analyze open files
    analyze_open_files();
    
    // Analyze resource usage
    analyze_resource_usage();
}

void cleanup_process_analyzer() {
    target_pid = -1;
    file_access_count = 0;
    unique_files_opened = 0;
}