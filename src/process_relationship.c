// process_relationship.c

#include "process_relationship.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <linux/limits.h>

static process_info_t *process_info = NULL;
static int process_count = 0;
static pthread_mutex_t process_mutex = PTHREAD_MUTEX_INITIALIZER;

// List of suspicious locations where executables shouldn't normally run from
static const char *suspicious_locations[] = {
    "/tmp/",
    "/dev/shm/",
    "/run/user/",
    "/var/tmp/",
    NULL
};

static const char *suspicious_parents[] = {
    "wget",
    "curl",
    "nc",
    "netcat",
    "python",
    "perl",
    "php",
    "ruby",
    NULL
};

bool init_process_relationship_analyzer(void) {
    process_info = (process_info_t*)calloc(MAX_TRACKED_PROCS, sizeof(process_info_t));
    return (process_info != NULL);
}

static int find_or_create_process(pid_t pid) {
    int i;
    
    // Look for existing entry
    for (i = 0; i < process_count; i++) {
        if (process_info[i].pid == pid) {
            return i;
        }
    }

    if (process_count < MAX_TRACKED_PROCS) {
        i = process_count++;
        process_info[i].pid = pid;
        process_info[i].suspicious_score = 0;
        
        // Get process information
        get_process_exe(pid, process_info[i].exec_path, MAX_PROC_PATH);
        get_process_cmdline(pid, process_info[i].cmdline, MAX_CMDLINE);
        get_process_cwd(pid, process_info[i].cwd, MAX_PROC_PATH);
        process_info[i].ppid = get_parent_pid(pid);
        
        return i;
    }

    int min_score = process_info[0].suspicious_score;
    int min_index = 0;
    
    for (i = 1; i < process_count; i++) {
        if (process_info[i].suspicious_score < min_score) {
            min_score = process_info[i].suspicious_score;
            min_index = i;
        }
    }
    
    process_info[min_index].pid = pid;
    process_info[min_index].suspicious_score = 0;
    get_process_exe(pid, process_info[min_index].exec_path, MAX_PROC_PATH);
    get_process_cmdline(pid, process_info[min_index].cmdline, MAX_CMDLINE);
    get_process_cwd(pid, process_info[min_index].cwd, MAX_PROC_PATH);
    process_info[min_index].ppid = get_parent_pid(pid);
    
    return min_index;
}

void track_process(pid_t pid) {
    pthread_mutex_lock(&process_mutex);
    int idx = find_or_create_process(pid);
    
    // Calculate suspiciousness score
    if (is_suspicious_location(process_info[idx].exec_path)) {
        process_info[idx].suspicious_score += 5;
    }
    if (is_suspicious_location(process_info[idx].cwd)) {
        process_info[idx].suspicious_score += 3;
    }
    
    if (has_suspicious_ancestry(pid)) {
        process_info[idx].suspicious_score += 4;
    }
    
    pthread_mutex_unlock(&process_mutex);
}

bool is_process_suspicious(pid_t pid) {
    bool result = false;
    pthread_mutex_lock(&process_mutex);
    
    for (int i = 0; i < process_count; i++) {
        if (process_info[i].pid == pid) {
            result = (process_info[i].suspicious_score >= 7);
            break;
        }
    }
    
    pthread_mutex_unlock(&process_mutex);
    return result;
}

pid_t get_parent_pid(pid_t pid) {
    char path[64];
    char buffer[256];
    pid_t ppid = 0;
    
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    
    FILE *f = fopen(path, "r");
    if (!f) {
        return 0;
    }
    
    if (fgets(buffer, sizeof(buffer), f)) {
        char *s = strrchr(buffer, ')');
        if (s) {
            int items = sscanf(s + 2, "%*c %d", &ppid);
            if (items != 1) {
                ppid = 0;
            }
        }
    }
    
    fclose(f);
    return ppid;
}

bool is_suspicious_location(const char *path) {
    if (!path || !*path) {
        return false;
    }
    
    for (int i = 0; suspicious_locations[i] != NULL; i++) {
        if (strncmp(path, suspicious_locations[i], strlen(suspicious_locations[i])) == 0) {
            return true;
        }
    }
    
    return false;
}

bool get_process_cmdline(pid_t pid, char *buffer, size_t size) {
    char path[64];
    
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        buffer[0] = '\0';
        return false;
    }

    ssize_t bytes_read = read(fd, buffer, size - 1);
    close(fd);
    
    if (bytes_read <= 0) {
        buffer[0] = '\0';
        return false;
    }
    
    // Replace null terminators with spaces for readability
    for (ssize_t i = 0; i < bytes_read - 1; i++) {
        if (buffer[i] == '\0') {
            buffer[i] = ' ';
        }
    }
    
    buffer[bytes_read] = '\0';
    return true;
}


bool get_process_exe(pid_t pid, char *buffer, size_t size) {
    char path[64];
    
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    
    ssize_t len = readlink(path, buffer, size - 1);
    if (len < 0) {
        buffer[0] = '\0';
        return false;
    }
    
    buffer[len] = '\0';
    return true;
}

bool get_process_cwd(pid_t pid, char *buffer, size_t size) {
    char path[64];
    
    snprintf(path, sizeof(path), "/proc/%d/cwd", pid);
    
    ssize_t len = readlink(path, buffer, size - 1);
    if (len < 0) {
        buffer[0] = '\0';
        return false;
    }
    
    buffer[len] = '\0';
    return true;
}


bool has_suspicious_ancestry(pid_t pid) {
    char exe_path[PATH_MAX];
    pid_t current_pid = pid;
    int depth = 0;
    
    // Trace back through parent processes
    while (current_pid > 1 && depth < 10) {
        if (!get_process_exe(current_pid, exe_path, sizeof(exe_path))) {
            break;
        }
        
        // Extract the base name from the path
        const char *base_name = strrchr(exe_path, '/');
        if (base_name) {
            base_name++; // Skip the slash
        } else {
            base_name = exe_path;
        }
        
        // Check if the executable name is in our suspicious list
        for (int i = 0; suspicious_parents[i] != NULL; i++) {
            if (strcmp(base_name, suspicious_parents[i]) == 0) {
                return true;
            }
        }
        
        // Check if running from suspicious location
        if (is_suspicious_location(exe_path)) {
            return true;
        }
        current_pid = get_parent_pid(current_pid);
        depth++;
    }
    
    return false;
}

void cleanup_process_relationship_analyzer(void) {
    if (process_info) {
        free(process_info);
        process_info = NULL;
    }
    process_count = 0;
}