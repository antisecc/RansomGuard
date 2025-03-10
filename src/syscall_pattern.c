// syscall_pattern.c

#include "syscall_pattern.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define SYS_open 2
#define SYS_close 3
#define SYS_read 0
#define SYS_write 1
#define SYS_rename 82
#define SYS_unlink 87
#define SYS_mkdir 83
#define SYS_rmdir 84

typedef struct {
    int syscalls[8];  
    int length;       
    pattern_type_t type;
    int weight;       
    const char *description;
} syscall_pattern_t;

static const syscall_pattern_t known_patterns[] = {
    {{SYS_open, SYS_write, SYS_close, SYS_rename}, 4, PATTERN_RANSOMWARE, 80, 
        "File modification followed by rename (possible encryption)"},
    
    {{SYS_open, SYS_read, SYS_write, SYS_close}, 4, PATTERN_SUSPICIOUS, 60,
        "Sequential read-modify-write pattern"},
    
    {{SYS_open, SYS_write, SYS_close, SYS_unlink}, 4, PATTERN_SUSPICIOUS, 75,
        "File creation followed by deletion of original"},
        
    {{0}, 0, PATTERN_NORMAL, 0, NULL}
};

typedef struct {
    pid_t pid;
    long syscall_history[SYSCALL_HISTORY_SIZE];
    struct timespec timestamps[SYSCALL_HISTORY_SIZE];
    int current_index;
    int total_syscalls;
    int suspicious_score;
} process_syscalls_t;

static process_syscalls_t *process_data = NULL;
static int process_count = 0;
static pthread_mutex_t syscall_mutex = PTHREAD_MUTEX_INITIALIZER;

bool init_syscall_pattern(void) {
    pthread_mutex_lock(&syscall_mutex);
    
    if (process_data != NULL) {
        free(process_data);
    }
    
    process_data = calloc(MAX_TRACKED_PROCESSES, sizeof(process_syscalls_t));
    if (process_data == NULL) {
        pthread_mutex_unlock(&syscall_mutex);
        return false;
    }
    
    process_count = 0;
    
    pthread_mutex_unlock(&syscall_mutex);
    return true;
}

static process_syscalls_t *find_process_data(pid_t pid) {
    for (int i = 0; i < process_count; i++) {
        if (process_data[i].pid == pid) {
            return &process_data[i];
        }
    }
    
    if (process_count < MAX_TRACKED_PROCESSES) {
        process_syscalls_t *proc = &process_data[process_count++];
        memset(proc, 0, sizeof(process_syscalls_t));
        proc->pid = pid;
        return proc;
    }
    
    return NULL;
}

static bool match_pattern(const long *history, int history_len, 
                        const syscall_pattern_t *pattern) {
    if (pattern->length > history_len) {
        return false;
    }
    
    for (int i = 0; i < pattern->length; i++) {
        if (history[i] != pattern->syscalls[i]) {
            return false;
        }
    }
    
    return true;
}

void record_syscall(pid_t pid, long syscall_nr, long *args, int arg_count) {
    if (pid <= 0) {
        return;
    }
    
    pthread_mutex_lock(&syscall_mutex);
    
    process_syscalls_t *proc = find_process_data(pid);
    if (proc == NULL) {
        pthread_mutex_unlock(&syscall_mutex);
        return;
    }
    
    proc->syscall_history[proc->current_index] = syscall_nr;
    clock_gettime(CLOCK_MONOTONIC, &proc->timestamps[proc->current_index]);
    proc->current_index = (proc->current_index + 1) % SYSCALL_HISTORY_SIZE;
    proc->total_syscalls++;
    
    pthread_mutex_unlock(&syscall_mutex);
}

static int analyze_process_patterns(process_syscalls_t *proc, 
                                  syscall_pattern_result_t *result) {
    if (proc->total_syscalls < 4) {  // Need minimum history
        return 0;
    }
    
    long linear_history[SYSCALL_HISTORY_SIZE];
    int history_len = proc->total_syscalls < SYSCALL_HISTORY_SIZE ? 
                     proc->total_syscalls : SYSCALL_HISTORY_SIZE;
    
    for (int i = 0; i < history_len; i++) {
        int idx = (proc->current_index - i - 1 + SYSCALL_HISTORY_SIZE) % SYSCALL_HISTORY_SIZE;
        linear_history[i] = proc->syscall_history[idx];
    }
    
    int max_confidence = 0;
    pattern_type_t worst_pattern = PATTERN_NORMAL;
    const char *description = NULL;
    
    for (int i = 0; known_patterns[i].length > 0; i++) {
        if (match_pattern(linear_history, history_len, &known_patterns[i])) {
            if (known_patterns[i].weight > max_confidence) {
                max_confidence = known_patterns[i].weight;
                worst_pattern = known_patterns[i].type;
                description = known_patterns[i].description;
            }
        }
    }
    
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int file_ops_count = 0;
    
    for (int i = 0; i < history_len; i++) {
        long syscall = linear_history[i];
        int idx = (proc->current_index - i - 1 + SYSCALL_HISTORY_SIZE) % SYSCALL_HISTORY_SIZE;
        struct timespec *ts = &proc->timestamps[idx];
        
        if ((now.tv_sec - ts->tv_sec) < 1 || 
           (now.tv_sec == ts->tv_sec && now.tv_nsec >= ts->tv_nsec)) {
            if (syscall == SYS_open || syscall == SYS_write || 
                syscall == SYS_rename || syscall == SYS_unlink) {
                file_ops_count++;
            }
        }
    }
    
    if (file_ops_count > 20) {  // More than 20 file ops per second
        if (max_confidence < 70) {
            max_confidence = 70;
            worst_pattern = PATTERN_SUSPICIOUS;
            description = "High frequency of file operations";
        }
    }
    
    if (worst_pattern != PATTERN_NORMAL) {
        result->pid = proc->pid;
        result->pattern_type = worst_pattern;
        result->confidence = max_confidence;
        result->description = description;
        return 1;
    }
    
    return 0;
}

int analyze_syscall_patterns(pid_t pid, syscall_pattern_result_t *results, int max_results) {
    if (results == NULL || max_results <= 0) {
        return 0;
    }
    
    int result_count = 0;
    
    pthread_mutex_lock(&syscall_mutex);
    
    if (pid > 0) {
        for (int i = 0; i < process_count; i++) {
            if (process_data[i].pid == pid) {
                result_count += analyze_process_patterns(
                    &process_data[i], &results[result_count]);
                break;
            }
        }
    } else {
        for (int i = 0; i < process_count && result_count < max_results; i++) {
            result_count += analyze_process_patterns(
                &process_data[i], &results[result_count]);
        }
    }
    
    pthread_mutex_unlock(&syscall_mutex);
    return result_count;
}

void cleanup_syscall_pattern(void) {
    pthread_mutex_lock(&syscall_mutex);
    
    if (process_data != NULL) {
        free(process_data);
        process_data = NULL;
    }
    
    process_count = 0;
    
    pthread_mutex_unlock(&syscall_mutex);
}