// behavioral_analysis.c

#include "behavioral_analysis.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

static file_activity_t *file_activities = NULL;
static int file_activity_count = 0;
static pthread_mutex_t activity_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    pid_t pid;
    int operations_per_minute;
    int unique_files_accessed;
    time_t last_check;
    int consecutive_writes;
    int renames_after_writes;
} process_stats_t;

#define MAX_PROCESSES 100
static process_stats_t process_stats[MAX_PROCESSES];
static int process_count = 0;

bool init_behavioral_analysis(void) {
    file_activities = (file_activity_t*)calloc(MAX_TRACKED_FILES, sizeof(file_activity_t));
    if (!file_activities) {
        perror("Failed to allocate memory for file activity tracking");
        return false;
    }
    
    memset(process_stats, 0, sizeof(process_stats));
    return true;
}

static int find_or_create_file_activity(const char *filename) {
    int i;
    
    for (i = 0; i < file_activity_count; i++) {
        if (strcmp(file_activities[i].filename, filename) == 0) {
            return i;
        }
    }
    
    if (file_activity_count < MAX_TRACKED_FILES) {
        i = file_activity_count++;
        strncpy(file_activities[i].filename, filename, MAX_PATH - 1);
        file_activities[i].filename[MAX_PATH - 1] = '\0';
        file_activities[i].history_index = 0;
        file_activities[i].first_seen = time(NULL);
        file_activities[i].entropy = 0;
        return i;
    }
    
    time_t oldest_time = time(NULL);
    int oldest_index = 0;
    
    for (i = 0; i < file_activity_count; i++) {
        if (file_activities[i].first_seen < oldest_time) {
            oldest_time = file_activities[i].first_seen;
            oldest_index = i;
        }
    }
    
    strncpy(file_activities[oldest_index].filename, filename, MAX_PATH - 1);
    file_activities[oldest_index].filename[MAX_PATH - 1] = '\0';
    file_activities[oldest_index].history_index = 0;
    file_activities[oldest_index].first_seen = time(NULL);
    file_activities[oldest_index].entropy = 0;
    
    return oldest_index;
}

static int find_or_create_process_stats(pid_t pid) {
    int i;
    
    for (i = 0; i < process_count; i++) {
        if (process_stats[i].pid == pid) {
            return i;
        }
    }
    
    if (process_count < MAX_PROCESSES) {
        i = process_count++;
        process_stats[i].pid = pid;
        process_stats[i].operations_per_minute = 0;
        process_stats[i].unique_files_accessed = 0;
        process_stats[i].last_check = time(NULL);
        process_stats[i].consecutive_writes = 0;
        process_stats[i].renames_after_writes = 0;
        return i;
    }
    
    int min_ops = process_stats[0].operations_per_minute;
    int min_index = 0;
    
    for (i = 1; i < process_count; i++) {
        if (process_stats[i].operations_per_minute < min_ops) {
            min_ops = process_stats[i].operations_per_minute;
            min_index = i;
        }
    }
    
    process_stats[min_index].pid = pid;
    process_stats[min_index].operations_per_minute = 0;
    process_stats[min_index].unique_files_accessed = 0;
    process_stats[min_index].last_check = time(NULL);
    process_stats[min_index].consecutive_writes = 0;
    process_stats[min_index].renames_after_writes = 0;
    
    return min_index;
}

void track_file_operation(const char *filename, file_operation_t operation, pid_t pid) {
    pthread_mutex_lock(&activity_mutex);
    
    int index = find_or_create_file_activity(filename);
    int history_idx = file_activities[index].history_index;
    
    file_activities[index].history[history_idx].operation = operation;
    file_activities[index].history[history_idx].timestamp = time(NULL);
    
    file_activities[index].history_index = (history_idx + 1) % FILE_HISTORY_SIZE;
    
    int proc_idx = find_or_create_process_stats(pid);
    process_stats[proc_idx].operations_per_minute++;
    
    time_t now = time(NULL);
    if (now - process_stats[proc_idx].last_check > 60) {
        process_stats[proc_idx].operations_per_minute = 1;
        process_stats[proc_idx].last_check = now;
    }
    
    if (operation == FILE_OP_WRITE) {
        process_stats[proc_idx].consecutive_writes++;
    } else if (operation == FILE_OP_RENAME && process_stats[proc_idx].consecutive_writes > 0) {
        process_stats[proc_idx].renames_after_writes++;
        process_stats[proc_idx].consecutive_writes = 0;
    } else {
        process_stats[proc_idx].consecutive_writes = 0;
    }
    
    pthread_mutex_unlock(&activity_mutex);
}

unsigned int calculate_file_entropy(const char *filename) {
    unsigned char buffer[4096];
    int fd, bytes_read;
    
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return 0;  // Can't calculate entropy
    }
    
    // Count byte frequencies
    unsigned int byte_count[256] = {0};
    unsigned int total_bytes = 0;
    
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        for (int i = 0; i < bytes_read; i++) {
            byte_count[buffer[i]]++;
        }
        total_bytes += bytes_read;
    }
    
    close(fd);
    
    if (total_bytes == 0) {
        return 0;
    }
    
    // Calculate Shannon entropy (simplified)
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byte_count[i] > 0) {
            double p = (double)byte_count[i] / total_bytes;
            entropy -= p * log2(p);
        }
    }
    
    // Normalize to 0-100 range (8 bits max entropy)
    return (unsigned int)((entropy / 8.0) * 100);
}

bool detect_suspicious_patterns(pid_t pid) {
    bool suspicious = false;
    int proc_idx = -1;
    
    pthread_mutex_lock(&activity_mutex);
    
    for (int i = 0; i < process_count; i++) {
        if (process_stats[i].pid == pid) {
            proc_idx = i;
            break;
        }
    }
    
    if (proc_idx == -1) {
        pthread_mutex_unlock(&activity_mutex);
        return false;
    }
    
    if (process_stats[proc_idx].operations_per_minute > 100) {
        suspicious = true;
    }
    
    if (process_stats[proc_idx].renames_after_writes > 10) {
        suspicious = true;
    }
    
    pthread_mutex_unlock(&activity_mutex);
    return suspicious;
}

void cleanup_behavioral_analysis(void) {
    if (file_activities) {
        free(file_activities);
        file_activities = NULL;
    }
    file_activity_count = 0;
    process_count = 0;
}