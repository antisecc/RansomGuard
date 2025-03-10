/**
 * behavioral_analysis.c
 * Implements detection of suspicious file operation patterns
 */

#include "behavioral_analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>

#define MAX_TRACKED_FILES 5000
#define OPERATION_HISTORY_SIZE 10
#define DEFAULT_OP_THRESHOLD 50  // Operations per minute threshold
#define DEFAULT_ENTROPY_THRESHOLD 0.8

// Track file operations with timestamps
typedef struct {
    char path[PATH_MAX];
    time_t timestamps[OPERATION_HISTORY_SIZE];
    int current_index;
    int total_operations;
    double last_entropy;
    file_op_type_t last_operations[OPERATION_HISTORY_SIZE];
} file_activity_t;

// Global state
static file_activity_t *tracked_files = NULL;
static int file_count = 0;
static pthread_mutex_t files_mutex = PTHREAD_MUTEX_INITIALIZER;
static int ops_per_minute_threshold = DEFAULT_OP_THRESHOLD;
static double entropy_threshold = DEFAULT_ENTROPY_THRESHOLD;

// Initialize the behavioral analysis module
bool init_behavioral_analysis(int max_files, int ops_threshold, double ent_threshold) {
    pthread_mutex_lock(&files_mutex);
    
    if (tracked_files != NULL) {
        free(tracked_files);
    }
    
    tracked_files = calloc(max_files, sizeof(file_activity_t));
    if (tracked_files == NULL) {
        pthread_mutex_unlock(&files_mutex);
        return false;
    }
    
    file_count = 0;
    ops_per_minute_threshold = ops_threshold > 0 ? ops_threshold : DEFAULT_OP_THRESHOLD;
    entropy_threshold = ent_threshold > 0 ? ent_threshold : DEFAULT_ENTROPY_THRESHOLD;
    
    pthread_mutex_unlock(&files_mutex);
    return true;
}

// Record a file operation
void record_file_operation(const char *path, file_op_type_t op_type, double entropy) {
    if (path == NULL || tracked_files == NULL) {
        return;
    }
    
    pthread_mutex_lock(&files_mutex);
    
    // Find existing file or create new entry
    int index = -1;
    for (int i = 0; i < file_count; i++) {
        if (strcmp(tracked_files[i].path, path) == 0) {
            index = i;
            break;
        }
    }
    
    if (index == -1) {
        // Create new entry if we have space
        if (file_count < MAX_TRACKED_FILES) {
            index = file_count++;
            strncpy(tracked_files[index].path, path, PATH_MAX - 1);
            tracked_files[index].path[PATH_MAX - 1] = '\0';
            tracked_files[index].current_index = 0;
            tracked_files[index].total_operations = 0;
        } else {
            // No space, can't track this file
            pthread_mutex_unlock(&files_mutex);
            return;
        }
    }
    
    // Record timestamp and operation
    file_activity_t *file = &tracked_files[index];
    file->timestamps[file->current_index] = time(NULL);
    file->last_operations[file->current_index] = op_type;
    file->last_entropy = entropy;
    file->total_operations++;
    file->current_index = (file->current_index + 1) % OPERATION_HISTORY_SIZE;
    
    pthread_mutex_unlock(&files_mutex);
}

// Check for suspicious activity based on recorded operations
bool detect_suspicious_activity(suspicious_activity_t *result) {
    if (tracked_files == NULL || result == NULL) {
        return false;
    }
    
    pthread_mutex_lock(&files_mutex);
    bool suspicious = false;
    time_t now = time(NULL);
    
    // Look for files with high activity rates and suspicious entropy
    for (int i = 0; i < file_count; i++) {
        file_activity_t *file = &tracked_files[i];
        int recent_ops = 0;
        
        // Count operations in the last minute
        for (int j = 0; j < OPERATION_HISTORY_SIZE; j++) {
            if (file->timestamps[j] > 0 && now - file->timestamps[j] < 60) {
                recent_ops++;
            }
        }
        
        // Check if activity exceeds threshold
        if (recent_ops >= ops_per_minute_threshold) {
            suspicious = true;
            strncpy(result->path, file->path, PATH_MAX - 1);
            result->path[PATH_MAX - 1] = '\0';
            result->operation_count = recent_ops;
            result->entropy = file->last_entropy;
            result->reason = REASON_HIGH_FREQUENCY;
            
            // If entropy is also high, this is very suspicious
            if (file->last_entropy > entropy_threshold) {
                result->reason = REASON_HIGH_FREQUENCY_AND_ENTROPY;
            }
            
            break;
        }
        
        // Check for file deletion after modification patterns
        bool has_write = false;
        bool has_delete = false;
        
        for (int j = 0; j < OPERATION_HISTORY_SIZE; j++) {
            if (file->last_operations[j] == FILE_OP_WRITE) {
                has_write = true;
            } else if (file->last_operations[j] == FILE_OP_DELETE || 
                       file->last_operations[j] == FILE_OP_RENAME) {
                has_delete = true;
            }
        }
        
        if (has_write && has_delete && file->last_entropy > entropy_threshold) {
            suspicious = true;
            strncpy(result->path, file->path, PATH_MAX - 1);
            result->path[PATH_MAX - 1] = '\0';
            result->operation_count = recent_ops;
            result->entropy = file->last_entropy;
            result->reason = REASON_WRITE_THEN_DELETE;
            break;
        }
    }
    
    pthread_mutex_unlock(&files_mutex);
    return suspicious;
}

// Clean up resources
void cleanup_behavioral_analysis(void) {
    pthread_mutex_lock(&files_mutex);
    if (tracked_files != NULL) {
        free(tracked_files);
        tracked_files = NULL;
    }
    file_count = 0;
    pthread_mutex_unlock(&files_mutex);
}