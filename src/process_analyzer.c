// process_analyzer.c
#include "process_analyzer.h"
#include "logger.h"  // For log_suspicious_activity
#include "hash_monitor.h"  // For monitor_file_hash
#include "file_monitor.h"  // For has_recent_network_activity
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include "process_relationship.h"
#include "behavioral_analysis.h"
#include "activity_scorer.h"

/*
// Comment out or remove this function as it's already defined in whitelist.c
bool is_process_whitelisted(pid_t pid, const char *path) {
    // Simplified implementation
    (void)pid;  // Avoid unused param warning
    (void)path;  // Avoid unused param warning
    return false;  // Default to not whitelisted
}
*/

/*
// Comment out or remove this function as it's already defined in file_monitor.c
bool is_process_suspicious(pid_t pid) {
    // Simplified implementation
    (void)pid;  // Avoid unused param warning
    return false;  // Default to not suspicious
}
*/

static pid_t target_pid = -1;
static int file_access_count = 0;
static int unique_files_opened = 0;

#define MAX_PATH 4096
#define SUSPICIOUS_FILE_ACCESS_THRESHOLD 50
#define PARENT_CACHE_SIZE 128

void process_file_event(const char * path,
    const char * full_path, file_op_type_t op_type,
      pid_t pid, double entropy, bool high_frequency) {
    if (path == NULL || full_path == NULL || pid <= 0) {
      return;
    }
  
    if (is_process_whitelisted(pid, NULL)) {
      if (entropy > 0.9 || is_process_suspicious(pid) || high_frequency) {
        char message[1024];
        snprintf(message, sizeof(message),
          "[WARNING] Whitelisted process %d performing high-risk operations with entropy %.2f",
          pid, entropy);
        log_suspicious_activity(message);
  
        risk_level_t risk = RISK_LEVEL_CRITICAL;
        record_file_operation(full_path, op_type, entropy);
  
        if ((op_type == FILE_OP_WRITE || op_type == FILE_OP_CREATE) && risk >= RISK_LEVEL_HIGH) {
          monitor_file_hash(full_path);
        }
      } else {
        return;
      }
    }
  
    process_suspicion_t parent_check = evaluate_file_modification(pid, full_path);
    bool is_suspicious = is_process_suspicious(pid);
    bool has_network = has_recent_network_activity(pid);
  
    score_operation_t score_op;
    switch (op_type) {
    case FILE_OP_CREATE:
      score_op = SCORE_FILE_CREATE;
      break;
    case FILE_OP_WRITE:
      score_op = SCORE_FILE_MODIFY;
      break;
    case FILE_OP_DELETE:
      score_op = SCORE_FILE_DELETE;
      break;
    case FILE_OP_RENAME:
      score_op = SCORE_FILE_RENAME;
      break;
    default:
      return;
    }
  
    risk_level_t risk = score_file_activity(pid, score_op, full_path, entropy);
  
    if (high_frequency) {
      risk = RISK_LEVEL_CRITICAL;
    } else if (parent_check.suspicious && parent_check.score > 50 && risk < RISK_LEVEL_HIGH) {
      risk = RISK_LEVEL_HIGH;
      char message[1024];
      snprintf(message, sizeof(message),
        "[ALERT] Suspicious file activity: %s, Parent process: %s",
        full_path, parent_check.reason);
      log_suspicious_activity(message);
    } else if ((is_suspicious || has_network) && risk < RISK_LEVEL_HIGH) {
      risk = RISK_LEVEL_MEDIUM;
    }
  
    if (has_network && (op_type == FILE_OP_WRITE || op_type == FILE_OP_CREATE) && entropy > 0.7) {
      char message[1024];
      char exec_path[PATH_MAX] = "unknown";
      char proc_path[64];
  
      snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
      readlink(proc_path, exec_path, sizeof(exec_path) - 1);
  
      snprintf(message, sizeof(message),
        "[CRITICAL] Process %d (%s) modifying files with high entropy while using network - ransomware behavior",
        pid, exec_path);
      log_suspicious_activity(message);
  
      risk = RISK_LEVEL_CRITICAL;
    }
  
    if (risk >= RISK_LEVEL_MEDIUM) {
      record_file_operation(full_path, op_type, entropy);
  
      if (risk >= RISK_LEVEL_HIGH && (op_type == FILE_OP_WRITE || op_type == FILE_OP_CREATE)) {
        monitor_file_hash(full_path);
      }
    }
  }



typedef struct {
    pid_t pid;
    pid_t parent_pid;
    char binary_path[MAX_PATH];
} parent_cache_entry_t;

static parent_cache_entry_t parent_cache[PARENT_CACHE_SIZE];
static int parent_cache_count = 0;

static void add_to_parent_cache(pid_t pid, pid_t parent_pid, const char *binary_path) {
    if (parent_cache_count >= PARENT_CACHE_SIZE) {
        return;
    }
    parent_cache[parent_cache_count].pid = pid;
    parent_cache[parent_cache_count].parent_pid = parent_pid;
    strncpy(parent_cache[parent_cache_count].binary_path, binary_path, MAX_PATH - 1);
    parent_cache[parent_cache_count].binary_path[MAX_PATH - 1] = '\0';
    parent_cache_count++;
}

static bool find_in_parent_cache(pid_t pid, pid_t *parent_pid, char *binary_path, size_t path_size) {
    for (int i = 0; i < parent_cache_count; i++) {
        if (parent_cache[i].pid == pid) {
            *parent_pid = parent_cache[i].parent_pid;
            strncpy(binary_path, parent_cache[i].binary_path, path_size - 1);
            binary_path[path_size - 1] = '\0';
            return true;
        }
    }
    return false;
}

static void init_parent_cache(void) {
    parent_cache_count = 0;
    memset(parent_cache, 0, sizeof(parent_cache));
}

bool init_process_analyzer(pid_t pid) {
    target_pid = pid;
    init_parent_cache();
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

static void analyze_open_files() {
    char fd_path[MAX_PATH];
    snprintf(fd_path, MAX_PATH, "/proc/%d/fd", target_pid);
    
    DIR *dir = opendir(fd_path);
    if (dir == NULL) {
        return;
    }
    
    int count = 0;
    struct dirent *entry;
    char target_path[MAX_PATH];
    char link_target[MAX_PATH];
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;  
        }
        
        // Check if combined path would be too long before creating it
        if (strlen(fd_path) + strlen(entry->d_name) + 2 > MAX_PATH) {
            // Path would be too long, skip this entry
            continue;
        }
        
        // Use safer string concatenation
        strcpy(target_path, fd_path);
        strcat(target_path, "/");
        strcat(target_path, entry->d_name);
        
        ssize_t len = readlink(target_path, link_target, MAX_PATH-1);
        if (len != -1) {
            link_target[len] = '\0';
            
            if (strncmp(link_target, "socket:", 7) &&
                strncmp(link_target, "pipe:", 5) &&
                strncmp(link_target, "anon_inode:", 11)) {
                count++;
                printf("PID %d has open file: %s\n", target_pid, link_target);
            }
        }
    }
    
    closedir(dir);
    
    file_access_count += count;
    unique_files_opened += count;
    
    if (file_access_count > SUSPICIOUS_FILE_ACCESS_THRESHOLD) {
        printf("[ALERT] Process %d accessing high number of files: %d\n", 
                target_pid, file_access_count);
        file_access_count = 0;  
    }
}

// Fix the analyze_resource_usage function
static void analyze_resource_usage() {
    char stat_path[MAX_PATH];
    snprintf(stat_path, MAX_PATH, "/proc/%d/stat", target_pid);
    
    FILE *stat_file = fopen(stat_path, "r");
    if (!stat_file) {
        return;
    }
    
    char comm[256];
    char state;
    int ppid;
    unsigned long utime = 0, stime = 0;
    
    // Fix the format string to avoid assignment suppression issues
    // Original: fscanf(stat_file, "%*d %s %c %d %*d %*d %*d %*d %*u %*lu %*lu %*lu %*lu %lu %lu", ...);
    
    // Read individual fields with separate fscanf calls
    int pid_dummy;
    fscanf(stat_file, "%d", &pid_dummy);  // Read pid (we already know it)
    fscanf(stat_file, " %255s", comm);    // Read comm
    fscanf(stat_file, " %c", &state);     // Read state
    fscanf(stat_file, " %d", &ppid);      // Read ppid
    
    // Skip to utime, stime (we need to skip 10 fields)
    for (int i = 0; i < 10; i++) {
        long dummy;
        fscanf(stat_file, " %ld", &dummy);
    }
    
    // Now read utime and stime
    fscanf(stat_file, " %lu %lu", &utime, &stime);
    
    printf("Process %d: state=%c, cpu_time=%lu\n", target_pid, state, utime+stime);
    
    fclose(stat_file);
}

void analyze_process() {
    if (target_pid <= 0) {
        return;
    }    
    char proc_path[MAX_PATH];
    snprintf(proc_path, MAX_PATH, "/proc/%d", target_pid);
    
    if (access(proc_path, F_OK) != 0) {
        printf("Process %d no longer exists\n", target_pid);
        return;
    }
    
    analyze_open_files();
    
    analyze_resource_usage();
}

void cleanup_process_analyzer() {
    target_pid = -1;
    file_access_count = 0;
    unique_files_opened = 0;
}

bool is_suspicious_location(const char *path) {
    const char *suspicious_dirs[] = {
        "/tmp/",
        "/dev/shm/",
        "/run/",
        "/var/tmp/",
        NULL
    };
    
    if (!path || path[0] == '\0')
        return false;
    
    for (int i = 0; suspicious_dirs[i] != NULL; i++) {
        if (strncmp(path, suspicious_dirs[i], strlen(suspicious_dirs[i])) == 0) {
            return true;
        }
    }
    
    return false;
}

bool get_parent_info(pid_t pid, pid_t *ppid, char *binary_path, size_t path_size) {
    if (!ppid || !binary_path || path_size == 0) {
        return false;
    }
    
    *ppid = -1;
    binary_path[0] = '\0';
    
    char stat_path[MAX_PATH];
    snprintf(stat_path, MAX_PATH, "/proc/%d/stat", pid);
    
    FILE *stat_file = fopen(stat_path, "r");
    if (!stat_file) {
        return false;
    }
    
    char comm[256];
    char state;
    
    int result = fscanf(stat_file, "%*d %s %c %d", comm, &state, ppid);
    fclose(stat_file);
    
    if (result != 3 || *ppid <= 0) {
        return false;
    }
    
    char exe_path[MAX_PATH];
    snprintf(exe_path, MAX_PATH, "/proc/%d/exe", *ppid);
    
    ssize_t len = readlink(exe_path, binary_path, path_size - 1);
    if (len <= 0) {
        return false;
    }
    
    binary_path[len] = '\0';
    return true;
}

bool is_trusted_binary(const char *binary_path) {
    const char *trusted_binaries[] = {
        "/bin/bash",
        "/usr/bin/bash",
        "/bin/dash",
        "/usr/bin/dash",
        "/bin/sh",
        "/usr/bin/sh",
        "/bin/nano",
        "/usr/bin/nano",
        "/bin/vim",
        "/usr/bin/vim",
        "/bin/vi",
        "/usr/bin/vi",
        "/usr/bin/emacs",
        "/bin/emacs",
        "/usr/bin/gedit",
        "/usr/bin/kate",
        "/usr/bin/kwrite",
        "/usr/bin/code",
        "/usr/bin/subl",
        "/usr/bin/atom",
        NULL
    };
    
    if (!binary_path || binary_path[0] == '\0')
        return false;
    
    for (int i = 0; trusted_binaries[i] != NULL; i++) {
        if (strcmp(binary_path, trusted_binaries[i]) == 0) {
            return true;
        }
    }
    
    return false;
}

// Fix the evaluate_file_modification function
process_suspicion_t evaluate_file_modification(pid_t pid, const char *file_path) {
    // Use file_path parameter to avoid unused warning
    (void)file_path;
    
    process_suspicion_t result = {0};  // Initialize all fields to 0/NULL
    result.suspicious = false;
    result.parent_pid = -1;
    result.score = 0;
    // binary_path and reason are already zeroed by {0}
    
    char binary_path[MAX_PATH] = {0};
    pid_t ppid = -1;
    
    if (!get_parent_info(pid, &ppid, binary_path, sizeof(binary_path))) {
        result.suspicious = true;
        result.score = 50;  
        snprintf(result.reason, sizeof(result.reason), "Unable to identify parent process for PID %d", pid);
        return result;
    }
    
    result.parent_pid = ppid;
    snprintf(result.binary_path, sizeof(result.binary_path), "%s", binary_path);
    
    // Use the existing check_suspicious_parent_child function
    int relationship_score = 0;
    char reason[256] = {0};
    
    if (check_suspicious_parent_child(ppid, pid, &relationship_score, reason, sizeof(reason))) {
        result.suspicious = true;
        result.score = relationship_score;
        snprintf(result.reason, sizeof(result.reason), "Suspicious parent-child: %s", reason);
        return result;
    }
    
    // Rest of the function same as before
    if (is_trusted_binary(binary_path)) {
        result.suspicious = false;
        result.score = 0;
        return result;
    }
    
    if (is_suspicious_location(binary_path)) {
        result.suspicious = true;
        result.score = 80;  
        snprintf(result.reason, sizeof(result.reason), 
                "Process %d from suspicious location: %s", ppid, binary_path);
        return result;
    }
    
    if (binary_path[0] == '\0') {
        result.suspicious = true;
        result.score = 40;  
        snprintf(result.reason, sizeof(result.reason), 
                "Unknown binary for parent process %d", ppid);
        return result;
    }
    
    result.suspicious = true;
    result.score = 30;  
    snprintf(result.reason, sizeof(result.reason), 
            "Untrusted binary: %s (PID: %d)", binary_path, ppid);
    
    return result;
}

// Use or remove unused functions
#pragma GCC diagnostic ignored "-Wunused-function"
// Alternative way to mark functions as used
static void unused_func_marker() {
    if (0) {  // This code never executes
        pid_t dummy_pid = 0;
        char dummy_path[10];
        add_to_parent_cache(dummy_pid, dummy_pid, dummy_path);
        find_in_parent_cache(dummy_pid, &dummy_pid, dummy_path, 10);
    }
}
