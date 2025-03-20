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

// susp activities
#define SCORE_HIGH_ENTROPY             10
#define SCORE_SUSPICIOUS_PARENT_CHILD   5
#define SCORE_HIGH_FREQUENCY_MOD        5
#define SCORE_RWX_PERMISSION           20
#define SCORE_NETWORK_CORRELATION      15
#define SCORE_DANGEROUS_SYSCALL        15
#define SCORE_MULTIPLE_PROCESSES        8
#define SCORE_UNUSUAL_TIME             10
#define SCORE_HIDDEN_FILE              12

// Score thresholds
#define DEFAULT_ALERT_THRESHOLD        20
#define HIGH_LOAD_THRESHOLD            30
#define CRITICAL_RESPONSE_THRESHOLD    50

static int current_alert_threshold = DEFAULT_ALERT_THRESHOLD;
static time_t last_threshold_update = 0;
static pthread_mutex_t threshold_mutex = PTHREAD_MUTEX_INITIALIZER;

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

static process_score_t *find_process_score(pid_t pid) {
    for (int i = 0; i < process_count; i++) {
        if (process_scores[i].pid == pid) {
            return &process_scores[i];
        }
    }
    
    if (process_count < MAX_TRACKED_PROCESSES) {
        process_score_t *score = &process_scores[process_count++];
        memset(score, 0, sizeof(process_score_t));
        score->pid = pid;
        score->last_operation = time(NULL);
        return score;
    }
    
    process_score_t *oldest = &process_scores[0];
    time_t now = time(NULL);
    
    for (int i = 1; i < process_count; i++) {
        if (now - process_scores[i].last_operation > now - oldest->last_operation) {
            oldest = &process_scores[i];
        }
    }
    
    memset(oldest, 0, sizeof(process_score_t));
    oldest->pid = pid;
    oldest->last_operation = time(NULL);
    return oldest;
}

static file_track_t *find_file_track(const char *path) {
    for (int i = 0; i < file_count; i++) {
        if (strcmp(file_tracks[i].path, path) == 0) {
            return &file_tracks[i];
        }
    }
    
    if (file_count < MAX_TRACKED_FILES) {
        file_track_t *track = &file_tracks[file_count++];
        strncpy(track->path, path, MAX_PATH_LENGTH - 1);
        track->path[MAX_PATH_LENGTH - 1] = '\0';
        track->last_access = time(NULL);
        track->access_count = 0;
        track->last_pid = 0;
        return track;
    }
    
    file_track_t *oldest = &file_tracks[0];
    time_t now = time(NULL);
    
    for (int i = 1; i < file_count; i++) {
        if (now - file_tracks[i].last_access > now - oldest->last_access) {
            oldest = &file_tracks[i];
        }
    }
    
    strncpy(oldest->path, path, MAX_PATH_LENGTH - 1);
    oldest->path[MAX_PATH_LENGTH - 1] = '\0';
    oldest->last_access = time(NULL);
    oldest->access_count = 0;
    oldest->last_pid = 0;
    return oldest;
}

static int score_file_extension(const char *path) {
    if (!path || !*path) return 0;
    
    const char *ext = strrchr(path, '.');
    if (!ext) return 0;
    ext++; 
    
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
    
    // Initialize dynamic threshold
    current_alert_threshold = DEFAULT_ALERT_THRESHOLD;
    last_threshold_update = time(NULL);
    
    pthread_mutex_unlock(&score_mutex);
    return true;
}

risk_level_t score_file_activity(pid_t pid, score_operation_t operation, const char *path, double entropy) {
    char exec_path[MAX_PATH_LENGTH];
    int score_increment = 0;
    
    if (get_exe_path(pid, exec_path, sizeof(exec_path)) && is_process_whitelisted(pid, exec_path)) {
        return RISK_LEVEL_NONE;  // Whitelisted processes get zero risk
    }
    
    pthread_mutex_lock(&score_mutex);
    
    process_score_t *proc = find_process_score(pid);
    if (!proc) {
        pthread_mutex_unlock(&score_mutex);
        return RISK_LEVEL_NONE;
    }
    
    file_track_t *file = find_file_track(path);
    file->last_access = time(NULL);
    file->access_count++;
    file->last_pid = pid;
    
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
    
    score_increment += score_file_extension(path);
    
    time_t now = time(NULL);
    if (now - proc->last_operation <= 60) {  
        proc->operations_per_min++;
        
        if (proc->operations_per_min > 20) {
            score_increment *= 2;  
        }
    } else {
        proc->operations_per_min = 1;
    }
    
    if (entropy > 0) {
        proc->avg_entropy = (proc->avg_entropy * proc->entropy_samples + entropy) / (proc->entropy_samples + 1);
        proc->entropy_samples++;
        
        // High entropy operations are very suspicious
        if (entropy > 0.8) {  // High entropy threshold
            proc->high_entropy_writes++;
            score_increment += 10;  // Substantial risk increase
        }
    }
    
    if (operation == SCORE_FILE_RENAME && proc->file_renames > proc->file_deletions) {
        score_increment += 5;
    }
    
    proc->total_score += score_increment;
    proc->last_operation = now;
    strncpy(proc->last_path, path, MAX_PATH_LENGTH - 1);
    proc->last_path[MAX_PATH_LENGTH - 1] = '\0';
    
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

/**
 * Update the alert threshold based on system load
 * Called periodically to adjust sensitivity
 */
void update_alert_threshold(void) {
    time_t now = time(NULL);
    
    if (now - last_threshold_update < 60) {
        return;
    }
    
    pthread_mutex_lock(&threshold_mutex);
    
    // Get system load average
    double loadavg[3];
    if (getloadavg(loadavg, 3) != -1) {
        double current_load = loadavg[0]; // 1-minute average
        
        // Adjust threshold based on load
        if (current_load > 5.0) {
            // Very high system load, increase threshold significantly
            current_alert_threshold = DEFAULT_ALERT_THRESHOLD * 2;
        } else if (current_load > 2.0) {
            // Moderately high load
            current_alert_threshold = (int)(DEFAULT_ALERT_THRESHOLD * (1.0 + (current_load - 2.0) * 0.2));
        } else {
            // Normal load
            current_alert_threshold = DEFAULT_ALERT_THRESHOLD;
        }
    }
    
    last_threshold_update = now;
    pthread_mutex_unlock(&threshold_mutex);
}

/**
 * Determine if current time is usual business hours
 * @return true if current time is unusual (nights, weekends)
 */
static bool is_unusual_time(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    if (tm_info->tm_wday == 0 || tm_info->tm_wday == 6) {
        return true;
    }
    
    if (tm_info->tm_hour < 8 || tm_info->tm_hour >= 18) {
        return true;
    }
    
    return false;
}

/**
 * Generate a detailed report based on scoring factors
 * 
 * @param pid Process ID
 * @param total_score Calculated score
 * @param factors Scoring factors used
 * @param report_buffer Buffer to store the report
 * @param buffer_size Size of the report buffer
 */
static void generate_score_report(pid_t pid, int total_score, 
                                 scoring_factors_t *factors, 
                                 char *report_buffer, size_t buffer_size) {
    if (!report_buffer || buffer_size < 10 || !factors) {
        return;
    }
    
    char process_name[256] = "unknown";
    char exe_path[MAX_PATH_LENGTH] = "unknown";
    
    get_exe_path(pid, exe_path, sizeof(exe_path));
    
    char *basename = strrchr(exe_path, '/');
    if (basename) {
        strncpy(process_name, basename + 1, sizeof(process_name) - 1);
        process_name[sizeof(process_name) - 1] = '\0';
    } else {
        if (strlen(exe_path) >= sizeof(process_name)) {
            // Path is too long - copy the last portion of the path which is usually the most important
            const char *basename = strrchr(exe_path, '/');
            if (basename) {
                strncpy(process_name, basename + 1, sizeof(process_name) - 1);
                process_name[sizeof(process_name) - 1] = '\0';
            } else {
                // Path doesn't contain '/' or other issue - copy as much as will fit
                strncpy(process_name, exe_path, sizeof(process_name) - 1);
                process_name[sizeof(process_name) - 1] = '\0';
            }
        } else {
            // Path fits - simple copy
            strcpy(process_name, exe_path);
        }
    }
    
    int risk_level = 1;
    if (total_score >= CRITICAL_RESPONSE_THRESHOLD) {
        risk_level = 4; // Critical
        snprintf(report_buffer, buffer_size, 
                "[CRITICAL] Process %d (%s) - Score: %d - Possible ransomware behavior",
                pid, process_name, total_score);
    } else if (total_score >= HIGH_LOAD_THRESHOLD) {
        risk_level = 3; // High
        snprintf(report_buffer, buffer_size, 
                "[HIGH RISK] Process %d (%s) - Score: %d - Suspicious activity detected",
                pid, process_name, total_score);
    } else {
        risk_level = 2; // Medium
        snprintf(report_buffer, buffer_size, 
                "[SUSPICIOUS] Process %d (%s) - Score: %d - Potentially suspicious activity",
                pid, process_name, total_score);
    }
    
    size_t offset = strlen(report_buffer);
    size_t remaining = buffer_size - offset;
    
    strncat(report_buffer, "\nFactors: ", remaining);
    offset = strlen(report_buffer);
    remaining = buffer_size - offset;
    
    if (factors->entropy > 0.7) {  // Assuming high entropy means > 0.7
        strncat(report_buffer, "High entropy file(s), ", remaining);
    }
    
    if (factors->suspicious_parent_child) {
        strncat(report_buffer, "Suspicious parent-child relationship, ", remaining);
    }
    
    if (factors->high_frequency) {
        strncat(report_buffer, "High frequency file modifications, ", remaining);
    }
    
    if (factors->rwx_permission) {
        strncat(report_buffer, "RWX permission changes, ", remaining);
    }
    
    if (factors->network_correlation) {
        strncat(report_buffer, "Network activity with file modifications, ", remaining);
    }
    
    if (factors->memory_injection) {
        strncat(report_buffer, "Memory code injection, ", remaining);
    }
    
    if (factors->unusual_time) {
        strncat(report_buffer, "Activity during unusual hours, ", remaining);
    }
    
    if (factors->affected_processes > 1) {
        offset = strlen(report_buffer);
        remaining = buffer_size - offset;
        snprintf(report_buffer + offset, remaining,
                "Multiple processes affected (%d), ", factors->affected_processes);
    }
    
    if (factors->path_count > 0) {
        offset = strlen(report_buffer);
        remaining = buffer_size - offset;
        strncat(report_buffer, "\nPaths: ", remaining);
        
        for (int i = 0; i < factors->path_count && i < 5; i++) {
            offset = strlen(report_buffer);
            remaining = buffer_size - offset;
            
            if (i > 0) {
                strncat(report_buffer, ", ", remaining);
                offset += 2;
                remaining = buffer_size - offset;
            }
            
            if (factors->paths[i]) {
                strncat(report_buffer, factors->paths[i], remaining);
            }
        }
    }
    
    offset = strlen(report_buffer);
    if (offset > 2 && report_buffer[offset-2] == ',' && report_buffer[offset-1] == ' ') {
        report_buffer[offset-2] = '\0';
    }
    
    offset = strlen(report_buffer);
    remaining = buffer_size - offset;
    
    if (risk_level >= 4) {
        snprintf(report_buffer + offset, remaining,
                "\nRecommended action: Suspend process and alert administrator immediately");
    } else if (risk_level >= 3) {
        snprintf(report_buffer + offset, remaining,
                "\nRecommended action: Increase monitoring and consider process isolation");
    } else {
        snprintf(report_buffer + offset, remaining,
                "\nRecommended action: Monitor for additional suspicious behavior");
    }
}

/**
 * Calculate a comprehensive score for suspicious activities
 * 
 * @param pid Process ID 
 * @param factors Various factors to consider in scoring
 * @return The calculated risk score
 */
int calculate_score(pid_t pid, scoring_factors_t *factors) {
    if (!factors) {
        return 0;
    }
    
    update_alert_threshold();
    
    int total_score = 0;
    
    if (factors->entropy > 0.0) {
        int entropy_score = (int)(factors->entropy * SCORE_HIGH_ENTROPY);
        total_score += entropy_score;
    }
    
    if (factors->suspicious_parent_child) {
        total_score += SCORE_SUSPICIOUS_PARENT_CHILD;
    }
    
    if (factors->high_frequency) {
        total_score += SCORE_HIGH_FREQUENCY_MOD;
    }
    
    if (factors->rwx_permission) {
        total_score += SCORE_RWX_PERMISSION;
    }
    
    if (factors->network_correlation) {
        total_score += SCORE_NETWORK_CORRELATION;
    }
    
    if (factors->memory_injection) {
        total_score += SCORE_MEMORY_INJECTION;
    }
    
    factors->unusual_time = is_unusual_time();
    if (factors->unusual_time) {
        total_score += SCORE_UNUSUAL_TIME;
    }
    
    if (factors->affected_processes > 1) {
        total_score += SCORE_MULTIPLE_PROCESSES;
    }
    
    if (factors->hidden_file) {
        total_score += SCORE_HIDDEN_FILE;
    }
    
    process_score_t *proc = NULL;
    
    pthread_mutex_lock(&score_mutex);
    
    // Find process score entry
    for (int i = 0; i < process_count; i++) {
        if (process_scores[i].pid == pid) {
            proc = &process_scores[i];
            break;
        }
    }
    
    if (proc) {
        if (proc->high_entropy_writes > 3) {
            total_score += 15; 
        }
        
        if (proc->file_renames > 5) {
            total_score += 10; 
        }
        
        if (proc->operations_per_min > 30) {
            total_score += 12; 
        }
    }
    
    pthread_mutex_unlock(&score_mutex);
    
    if (total_score >= current_alert_threshold) {
        char report[2048];
        generate_score_report(pid, total_score, factors, report, sizeof(report));
        
        log_suspicious_activity(report);
        
        pthread_mutex_lock(&score_mutex);
        
        if (!proc) {
            proc = find_process_score(pid);
        }
        
        if (proc) {
            proc->total_score += total_score / 2; 
        }
        
        pthread_mutex_unlock(&score_mutex);
        
        if (total_score >= CRITICAL_RESPONSE_THRESHOLD) {
            char crit_msg[256];
            snprintf(crit_msg, sizeof(crit_msg), 
                    "[CRITICAL] Requesting termination of process %d - Score: %d", 
                    pid, total_score);
            log_suspicious_activity(crit_msg);
            
        }
    }
    
    return total_score;
}

/**
 * Score a syscall event
 * 
 * @param pid Process ID
 * @param event_type Type of syscall event
 * @param path Path involved (if any) or NULL
 * @param entropy Entropy value (if applicable) or 0.0
 * @return Risk score calculated
 */
int score_syscall_event(pid_t pid, int event_type, const char *path, double entropy) {
    scoring_factors_t factors = {0};
    
    factors.entropy = entropy;
    
    if (path) {
        factors.paths[0] = (char *)path;
        factors.path_count = 1;
        
        const char *basename = strrchr(path, '/');
        if (basename && basename[1] == '.') {
            factors.hidden_file = true;
        }
    }
    
    switch (event_type) {
        case SCORE_MEMORY_INJECTION:
            factors.memory_injection = true;
            break;
            
        case SCORE_MEMORY_PROTECTION:
        case SCORE_MEMORY_MAPPING:
            factors.rwx_permission = true;
            break;
            
    }
    return calculate_score(pid, &factors);
}

/**
 * Score network and file activity correlation
 * 
 * @param pid Process ID
 * @param suspicion_score Pre-calculated suspicion score (0-100)
 * @return Risk score calculated
 */
int score_network_file_activity(pid_t pid, int suspicion_score) {
    scoring_factors_t factors = {0};
    factors.network_correlation = true;
    
    int base_score = calculate_score(pid, &factors);
    int calculated_score = suspicion_score / 2;
    
    // Return the higher of the two scores
    return (calculated_score > base_score) ? calculated_score : base_score;
}

/**
 * Score a multi-factor event with detailed information
 * 
 * @param pid Process ID
 * @param factors Detailed scoring factors
 * @return Risk score calculated
 */
int score_detailed_event(pid_t pid, scoring_factors_t *factors) {
    return calculate_score(pid, factors);
}

/**
 * Track network and file activity correlation
 */
bool track_network_and_file_activity(pid_t pid, int event_type, const char *path, 
                                   int socket_family, int socket_type, int port, double entropy) {
    // Simple implementation for now
    char message[512];
    snprintf(message, sizeof(message), 
            "[NETWORK] Process %d correlating network activity with file %s (entropy: %.2f)",
            pid, path, entropy);
    
    // Avoid unused parameter warnings
    (void)event_type;
    (void)socket_family;
    (void)socket_type;
    (void)port;
    
    // Only log at high verbosity or high entropy
    if (entropy > 0.7) {
        log_suspicious_activity(message);
        return true;
    }
    
    return false;
}