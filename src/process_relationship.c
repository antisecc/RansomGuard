// process_relationship.c

#include "process_relationship.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>

#define FORK_TRACK_SIZE 64 
#define MAX_PROCESSES 256

void init_fork_tracker(void);
void init_relationship_cache(void);

typedef struct {
    pid_t parent_pid;                    
    time_t first_fork_time;        
    int fork_count;               
    bool reported;                          
} fork_track_t;

static fork_track_t fork_tracker[FORK_TRACK_SIZE];
static int fork_track_count = 0;
static time_t fork_time_window = 5; 

#define RELATIONSHIP_CACHE_SIZE 128
typedef struct {
    pid_t parent_pid;
    pid_t child_pid;
    char parent_path[PATH_MAX];
    char child_path[PATH_MAX];
    time_t timestamp;
    int suspicion_score;
    bool suspicious;
    char reason[256];
} relationship_cache_entry_t;

static relationship_cache_entry_t relationship_cache[RELATIONSHIP_CACHE_SIZE];
static int relationship_cache_next = 0;

typedef struct {
    const char *parent_pattern;       
    const char *child_pattern;        
    int suspicion_score;                      
    const char *description;             
} suspicious_pair_t;


static const suspicious_pair_t suspicious_pairs[] = {
    {"python", "nc", 80, "Python script spawning netcat (possible reverse shell)"},
    {"python", "bash", 60, "Python script spawning bash (possible command injection)"},
    {"php", "bash", 70, "PHP spawning shell (possible webshell)"},
    {"apache2", "bash", 75, "Web server spawning shell (possible RCE)"},
    {"nginx", "bash", 75, "Web server spawning shell (possible RCE)"},
    {"python", "chmod", 65, "Python script changing file permissions"},
    {"bash", "gcc", 50, "Shell compiling code (possible malware compilation)"},
    {"java", "bash", 60, "Java process spawning shell (possible exploitation)"},
    {"/tmp/", "/tmp/", 90, "Process in /tmp spawning another process in /tmp"},
    {"/dev/shm/", "/dev/shm/", 95, "Process in shared memory spawning another process"},
    {"wget", "chmod", 85, "Download followed by permission change (common malware pattern)"},
    {"curl", "chmod", 85, "Download followed by permission change (common malware pattern)"},
    {"svchost.exe", "powershell", 90, "Windows service host spawning PowerShell (via Wine/emulation)"},
    {NULL, NULL, 0, NULL}
};

static const char *suspicious_paths[] = {
    "/tmp/", 
    "/dev/shm/", 
    "/run/user/",
    "/var/tmp/",
    NULL
};

static process_info_t process_cache[MAX_PROCESSES] __attribute__((unused));
static int process_count = 0;

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
    init_fork_tracker();
    init_relationship_cache();
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
    
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        return 0;
    }
    
    process_count = 0;
    struct dirent *entry;
    
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

void init_fork_tracker(void) {
    memset(fork_tracker, 0, sizeof(fork_tracker));
    fork_track_count = 0;
}

void init_relationship_cache(void) {
    memset(relationship_cache, 0, sizeof(relationship_cache));
    relationship_cache_next = 0;
}

bool track_fork(pid_t parent_pid) {
    time_t now = time(NULL);
    bool is_suspicious = false;
    
    for (int i = 0; i < fork_track_count; i++) {
        if (fork_tracker[i].parent_pid == parent_pid) {
            if (now - fork_tracker[i].first_fork_time <= fork_time_window) {
                fork_tracker[i].fork_count++;
                
                if (fork_tracker[i].fork_count >= 3 && !fork_tracker[i].reported) {
                    is_suspicious = true;
                    fork_tracker[i].reported = true;
                }
            } else {
                fork_tracker[i].first_fork_time = now;
                fork_tracker[i].fork_count = 1;
                fork_tracker[i].reported = false;
            }
            return is_suspicious;
        }
    }
    
    if (fork_track_count < FORK_TRACK_SIZE) {
        fork_tracker[fork_track_count].parent_pid = parent_pid;
        fork_tracker[fork_track_count].first_fork_time = now;
        fork_tracker[fork_track_count].fork_count = 1;
        fork_tracker[fork_track_count].reported = false;
        fork_track_count++;
    } else {
        int oldest = 0;
        for (int i = 1; i < FORK_TRACK_SIZE; i++) {
            if (fork_tracker[i].first_fork_time < fork_tracker[oldest].first_fork_time) {
                oldest = i;
            }
        }
        fork_tracker[oldest].parent_pid = parent_pid;
        fork_tracker[oldest].first_fork_time = now;
        fork_tracker[oldest].fork_count = 1;
        fork_tracker[oldest].reported = false;
    }
    
    return false;
}

bool path_contains(const char *path, const char *pattern) {
    if (pattern[0] == '/') {
        return strncmp(path, pattern, strlen(pattern)) == 0;
    }
    
    return strstr(path, pattern) != NULL;
}

bool lookup_relationship_cache(pid_t parent_pid, pid_t child_pid, 
                              int *score, char *reason, size_t reason_size) {
    time_t now = time(NULL);
    
    for (int i = 0; i < RELATIONSHIP_CACHE_SIZE; i++) {
        relationship_cache_entry_t *entry = &relationship_cache[i];
        
        if (entry->parent_pid == parent_pid && entry->child_pid == child_pid) {
            if (now - entry->timestamp < 30) {
                if (score) *score = entry->suspicion_score;
                if (reason && reason_size > 0) {
                    strncpy(reason, entry->reason, reason_size - 1);
                    reason[reason_size - 1] = '\0';
                }
                return entry->suspicious;
            }
        }
    }
    
    return false;
}

void add_to_relationship_cache(pid_t parent_pid, pid_t child_pid, 
                              const char *parent_path, const char *child_path,
                              bool suspicious, int score, const char *reason) {
    relationship_cache_entry_t *entry = &relationship_cache[relationship_cache_next];
    
    entry->parent_pid = parent_pid;
    entry->child_pid = child_pid;
    entry->timestamp = time(NULL);
    entry->suspicious = suspicious;
    entry->suspicion_score = score;
    
    if (parent_path) {
        strncpy(entry->parent_path, parent_path, PATH_MAX - 1);
        entry->parent_path[PATH_MAX - 1] = '\0';
    } else {
        entry->parent_path[0] = '\0';
    }
    
    if (child_path) {
        strncpy(entry->child_path, child_path, PATH_MAX - 1);
        entry->child_path[PATH_MAX - 1] = '\0';
    } else {
        entry->child_path[0] = '\0';
    }
    
    if (reason) {
        strncpy(entry->reason, reason, sizeof(entry->reason) - 1);
        entry->reason[sizeof(entry->reason) - 1] = '\0';
    } else {
        entry->reason[0] = '\0';
    }
    
    relationship_cache_next = (relationship_cache_next + 1) % RELATIONSHIP_CACHE_SIZE;
}

bool check_suspicious_parent_child(pid_t parent_pid, pid_t child_pid, 
                                  int *suspicion_score, char *reason_buffer, 
                                  size_t reason_size) {
    char parent_path[PATH_MAX] = {0};
    char child_path[PATH_MAX] = {0};
    bool is_suspicious = false;
    int score = 0;
    char reason[256] = {0};
    
    if (parent_pid <= 0 || child_pid <= 0) {
        return false;
    }
    
    if (lookup_relationship_cache(parent_pid, child_pid, &score, reason, sizeof(reason))) {
        if (suspicion_score) *suspicion_score = score;
        if (reason_buffer && reason_size > 0) {
            strncpy(reason_buffer, reason, reason_size - 1);
            reason_buffer[reason_size - 1] = '\0';
        }
        return true;
    }
    
    if (track_fork(parent_pid)) {
        is_suspicious = true;
        score = 70;
        snprintf(reason, sizeof(reason), 
                "Process %d is rapidly spawning child processes (possible fork bomb or ransomware)", 
                parent_pid);
                
        add_to_relationship_cache(parent_pid, child_pid, NULL, NULL, 
                                 true, score, reason);
                                 
        if (suspicion_score) *suspicion_score = score;
        if (reason_buffer && reason_size > 0) {
            strncpy(reason_buffer, reason, reason_size - 1);
            reason_buffer[reason_size - 1] = '\0';
        }
        return true;
    }
    
    char proc_path[PATH_MAX];
    snprintf(proc_path, PATH_MAX, "/proc/%d/exe", parent_pid);
    ssize_t len = readlink(proc_path, parent_path, PATH_MAX - 1);
    if (len <= 0) {
        track_fork(parent_pid);
        return false;
    }
    parent_path[len] = '\0';
    
    snprintf(proc_path, PATH_MAX, "/proc/%d/exe", child_pid);
    len = readlink(proc_path, child_path, PATH_MAX - 1);
    if (len <= 0) {
        for (int i = 0; suspicious_paths[i] != NULL; i++) {
            if (strncmp(parent_path, suspicious_paths[i], strlen(suspicious_paths[i])) == 0) {
                is_suspicious = true;
                score = 60;
                snprintf(reason, sizeof(reason), 
                        "Process from suspicious location %s spawned unidentifiable child",
                        parent_path);
                break;
            }
        }
        
        add_to_relationship_cache(parent_pid, child_pid, parent_path, NULL,
                                 is_suspicious, score, reason);
        
        if (suspicion_score) *suspicion_score = score;
        if (reason_buffer && reason_size > 0 && is_suspicious) {
            strncpy(reason_buffer, reason, reason_size - 1);
            reason_buffer[reason_size - 1] = '\0';
        }
        return is_suspicious;
    }
    child_path[len] = '\0';
    
    for (int i = 0; suspicious_pairs[i].parent_pattern != NULL; i++) {
        if (path_contains(parent_path, suspicious_pairs[i].parent_pattern) &&
            path_contains(child_path, suspicious_pairs[i].child_pattern)) {
            is_suspicious = true;
            score = suspicious_pairs[i].suspicion_score;
            snprintf(reason, sizeof(reason), "%s", suspicious_pairs[i].description);
            break;
        }
    }
    
    if (!is_suspicious) {
        bool parent_suspicious = false;
        bool child_suspicious = false;
        
        for (int i = 0; suspicious_paths[i] != NULL; i++) {
            if (strncmp(parent_path, suspicious_paths[i], strlen(suspicious_paths[i])) == 0) {
                parent_suspicious = true;
            }
            if (strncmp(child_path, suspicious_paths[i], strlen(suspicious_paths[i])) == 0) {
                child_suspicious = true;
            }
        }
        
        if (parent_suspicious && child_suspicious) {
            is_suspicious = true;
            score = 85;
            snprintf(reason, sizeof(reason), 
                    "Both parent (%s) and child (%s) processes are running from suspicious locations",
                    parent_path, child_path);
        } 
        else if (parent_suspicious) {
            is_suspicious = true;
            score = 60;
            snprintf(reason, sizeof(reason), 
                    "Process from suspicious location (%s) spawned child (%s)",
                    parent_path, child_path);
        }
    }
    
    add_to_relationship_cache(parent_pid, child_pid, parent_path, child_path,
                             is_suspicious, score, reason);
    
    if (suspicion_score) *suspicion_score = score;
    if (reason_buffer && reason_size > 0 && is_suspicious) {
        strncpy(reason_buffer, reason, reason_size - 1);
        reason_buffer[reason_size - 1] = '\0';
    }
    
    return is_suspicious;
}