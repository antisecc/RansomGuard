/**
 * activity_scorer.c - Scores file activities to identify suspicious patterns
 */

#include "activity_scorer.h"
#include "whitelist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <limits.h>

#define MAX_TRACKED_PROCESSES 100
#define MAX_TRACKED_FILES 1000
#define MAX_PATH_LENGTH 1024

// Per-process scoring information
typedef struct {
    pid_t pid;
    int total_score;
    int operations_per_min;
    time_t last_operation;
    char last_path[MAX_PATH_LENGTH];
    int file_renames;
    int file_deletions;
    int high_entropy_writes;
    double avg_entropy;
    int entropy_samples;
} process_score_t;

// Per-file tracking information
typedef struct {
    char path[MAX_PATH_LENGTH];
    pid_t last_pid;
    time_t last_access;
    int access_count;
} file_track_t;

// Global state
static process_score_t *process_scores = NULL;
static file_track_t *file_tracks = NULL;
static int process_count = 0;
static int file_count = 0;
static pthread_mutex_t score_mutex = PTHREAD_MUTEX_INITIALIZER;

// Risk thresholds
#define RISK_THRESHOLD_LOW      10
#define RISK_THRESHOLD_MEDIUM   25
#define RISK_THRESHOLD_HIGH     50
#define RISK_THRESHOLD_CRITICAL 100

// Get executable path for a pid
static bool get_exe_path(pid_t pid, char *buffer, size_t buffer_size) {
    char proc_path[64];
    
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(proc_path, buffer, buffer_size - 1);
    
    if (len < 0) {
        buffer[0] = '\0';
        return false;
    }
    
    buffer[len] = '\0';
    return true;
}

// Find or create process score entry
static process_score_t *find_process_score(pid_t pid) {
    // Look for existing entry
    for (int i = 0; i < process_count; i++) {
        if (process_scores[i].pid == pid) {
            return &process_scores[i];
        }
    }
    
    // Create new entry if possible
    if (process_count < MAX_TRACKED_PROCESSES) {
        process_score_t *score = &process_scores[process_count++];
        memset(score, 0, sizeof(process_score_t));
        score->pid = pid;
        score->last_operation = time(NULL);
        return score;
    }
    
    // Find least active process to replace
    process_score_t *oldest = &process_scores[0];
    time_t now = time(NULL);
    
    for (int i = 1; i < process_count; i++) {
        if (now - process_scores[i].last_operation > now - oldest->last_operation) {
            oldest = &process_scores[i];
        }
    }
    
    // Reset and return
    memset(oldest, 0, sizeof(process_score_t));
    oldest->pid = pid;
    oldest->last_operation = time(NULL);
    return oldest;
}

// Find or create file tracking entry
static file_track_t *find_file_track(const char *path) {
    // Look for existing entry
    for (int i = 0; i < file_count; i++) {
        if (strcmp(file_tracks[i].path, path) == 0) {
            return &file_tracks[i];
        }
    }
    
    // Create new entry if possible
    if (file_count < MAX_TRACKED_FILES) {
        file_track_t *track = &file_tracks[file_count++];
        strncpy(track->path, path, MAX_PATH_LENGTH - 1);
        track->path[MAX_PATH_LENGTH - 1] = '\0';
        track->last_access = time(NULL);
        track->access_count = 0;
        track->last_pid = 0;
        return track;
    }
    
    // Find least recently used file to replace
    file_track_t *oldest = &file_tracks[0];
    time_t now = time(NULL);
    
    for (int i = 1; i < file_count; i++) {
        if (now - file_tracks[i].last_access > now - oldest->last_access) {
            oldest = &file_tracks[i];
        }
    }
    
    // Reset and return
    strncpy(oldest->path, path, MAX_PATH_LENGTH - 1);
    oldest->path[MAX_PATH_LENGTH - 1] = '\0';
    oldest->last_access = time(NULL);
    oldest->access_count = 0;
    oldest->last_pid = 0;
    return oldest;
}

// Calculate file extension risk score
// Returns higher values for extensions commonly targeted by ransomware
static int score_file_extension(const char *path) {
    // Skip if no path
    if (!path || !*path) return 0;
    
    // Get file extension
    const char *ext = strrchr(path, '.');
    if (!ext) return 0;
    ext++; // Skip the dot
    
    // Common high-value extensions targeted by ransomware
    static const char *high_value_extensions[] = {
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf",
        "jpg", "jpeg", "png", "gif", "psd", "ai", "svg",
        "mp3", "mp4", "mov", "avi", "mkv", "zip", "rar",
        "sql", "mdb", "accdb", "dbf", "tax", "pst", "key",
        "wallet", "bitcoin", "sql", "db", NULL
    };
    
    // Check for high-value extensions
    for (int i = 0; high_value_extensions[i]; i++) {
        if (strcasecmp(ext, high_value_extensions[i]) == 0) {
            return 5;  // High risk score
        }
    }
    
    return 1;  // Default risk
}

// Initialize the activity scorer
bool init_activity_scorer(void) {
    pthread_mutex_lock(&score_mutex);
    
    if (process_scores != NULL) {
        free(process_scores);
    }
    
    if (file_tracks != NULL) {
        free(file_tracks);
    }
    
    process_scores = calloc(MAX_TRACKED_PROCESSES, sizeof(process_score_t));
    if (process_scores == NULL) {
        pthread_mutex_unlock(&score_mutex);
        return false;
    }
    
    file_tracks = calloc(MAX_TRACKED_FILES, sizeof(file_track_t));
    if (file_tracks == NULL) {
        free(process_scores);
        process_scores = NULL;
        pthread_mutex_unlock(&score_mutex);
        return false;
    }
    
    process_count = 0;
    file_count = 0;
    
    pthread_mutex_unlock(&score_mutex);
    return true;
}

// Score a file operation
risk_level_t score_file_activity(pid_t pid, score_operation_t operation, const char *path, double entropy) {
    char exec_path[MAX_PATH_LENGTH];
    int score_increment = 0;
    
    // Check if process is whitelisted
    if (get_exe_path(pid, exec_path, sizeof(exec_path)) && is_process_whitelisted(pid, exec_path)) {
        return RISK_LEVEL_NONE;  // Whitelisted processes get zero risk
    }
    
    pthread_mutex_lock(&score_mutex);
    
    // Get process score entry
    process_score_t *proc = find_process_score(pid);
    if (!proc) {
        pthread_mutex_unlock(&score_mutex);
        return RISK_LEVEL_NONE;
    }
    
    // Update file tracking
    file_track_t *file = find_file_track(path);
    file->last_access = time(NULL);
    file->access_count++;
    file->last_pid = pid;
    
    // Base score for the operation type
    switch (operation) {
        case SCORE_FILE_CREATE:
            score_increment = 1;
            break;
            
        case SCORE_FILE_MODIFY:
            score_increment = 2;
            break;
            
        case SCORE_FILE_DELETE:
            score_increment = 3;
            proc->file_deletions++;
            break;
            
        case SCORE_FILE_RENAME:
            score_increment = 4;
            proc->file_renames++;
            break;
    }
    
    // Add file extension score (higher for valuable file types)
    score_increment += score_file_extension(path);
    
    // Check operation frequency
    time_t now = time(NULL);
    if (now - proc->last_operation <= 60) {  // Within a minute
        proc->operations_per_min++;
        
        // High frequency operations are more suspicious
        if (proc->operations_per_min > 20) {
            score_increment *= 2;  // Double score for high frequency
        }
    } else {
        // Reset counter for new minute
        proc->operations_per_min = 1;
    }
    
    // Track high entropy writes (potential encryption)
    if (entropy > 0) {
        // Update average entropy
        proc->avg_entropy = (proc->avg_entropy * proc->entropy_samples + entropy) / (proc->entropy_samples + 1);
        proc->entropy_samples++;
        
        // High entropy operations are very suspicious
        if (entropy > 0.8) {  // High entropy threshold
            proc->high_entropy_writes++;
            score_increment += 10;  // Substantial risk increase
        }
    }
    
    // Check for rename after modification pattern (common in ransomware)
    if (operation == SCORE_FILE_RENAME && proc->file_renames > proc->file_deletions) {
        score_increment += 5;
    }
    
    // Update process score
    proc->total_score += score_increment;
    proc->last_operation = now;
    strncpy(proc->last_path, path, MAX_PATH_LENGTH - 1);
    proc->last_path[MAX_PATH_LENGTH - 1] = '\0';
    
    // Determine current risk level
    risk_level_t risk;
    if (proc->total_score >= RISK_THRESHOLD_CRITICAL) {
        risk = RISK_LEVEL_CRITICAL;
    } else if (proc->total_score >= RISK_THRESHOLD_HIGH) {
        risk = RISK_LEVEL_HIGH;
    } else if (proc->total_score >= RISK_THRESHOLD_MEDIUM) {
        risk = RISK_LEVEL_MEDIUM;
    } else if (proc->total_score >= RISK_THRESHOLD_LOW) {
        risk = RISK_LEVEL_LOW;
    } else {
        risk = RISK_LEVEL_NONE;
    }
    
    pthread_mutex_unlock(&score_mutex);
    return risk;
}

// Get the cumulative risk score for a process
risk_level_t get_process_risk_level(pid_t pid) {
    risk_level_t risk = RISK_LEVEL_NONE;
    
    pthread_mutex_lock(&score_mutex);
    
    for (int i = 0; i < process_count; i++) {
        if (process_scores[i].pid == pid) {
            int score = process_scores[i].total_score;
            
            if (score >= RISK_THRESHOLD_CRITICAL) {
                risk = RISK_LEVEL_CRITICAL;
            } else if (score >= RISK_THRESHOLD_HIGH) {
                risk = RISK_LEVEL_HIGH;
            } else if (score >= RISK_THRESHOLD_MEDIUM) {
                risk = RISK_LEVEL_MEDIUM;
            } else if (score >= RISK_THRESHOLD_LOW) {
                risk = RISK_LEVEL_LOW;
            }
            
            break;
        }
    }
    
    pthread_mutex_unlock(&score_mutex);
    return risk;
}

// Reset scores for a process
void reset_process_scores(pid_t pid) {
    pthread_mutex_lock(&score_mutex);
    
    for (int i = 0; i < process_count; i++) {
        if (process_scores[i].pid == pid) {
            process_scores[i].total_score = 0;
            process_scores[i].operations_per_min = 0;
            process_scores[i].file_deletions = 0;
            process_scores[i].file_renames = 0;
            process_scores[i].high_entropy_writes = 0;
            process_scores[i].avg_entropy = 0;
            process_scores[i].entropy_samples = 0;
            break;
        }
    }
    
    pthread_mutex_unlock(&score_mutex);
}

// Clean up resources
void cleanup_activity_scorer(void) {
    pthread_mutex_lock(&score_mutex);
    
    if (process_scores != NULL) {
        free(process_scores);
        process_scores = NULL;
    }
    
    if (file_tracks != NULL) {
        free(file_tracks);
        file_tracks = NULL;
    }
    
    process_count = 0;
    file_count = 0;
    
    pthread_mutex_unlock(&score_mutex);
}