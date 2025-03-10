/**
 * whitelist.c - Manages process whitelisting to reduce false positives
 */

#include "whitelist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#include <sys/stat.h>

#define MAX_WHITELIST_ENTRIES 100
#define MAX_PATH_LENGTH 1024

// Whitelist entries
typedef struct {
    char pattern[MAX_PATH_LENGTH];
    bool is_prefix;  // If true, match as prefix; if false, exact match
} whitelist_entry_t;

// Global state
static whitelist_entry_t *whitelist = NULL;
static int whitelist_count = 0;
static pthread_mutex_t whitelist_mutex = PTHREAD_MUTEX_INITIALIZER;

// Default whitelist of common editors and utilities
static const char *default_whitelist[] = {
    "/bin/nano",
    "/usr/bin/nano",
    "/bin/vi",
    "/usr/bin/vi",
    "/bin/vim",
    "/usr/bin/vim",
    "/bin/emacs",
    "/usr/bin/emacs",
    "/bin/touch",
    "/usr/bin/touch",
    "/bin/cp",
    "/usr/bin/cp",
    "/bin/mv",
    "/usr/bin/mv",
    "/bin/bash",
    "/usr/bin/bash",
    "/usr/lib/git-core/",  // Git operations (prefix)
    "/usr/bin/python",     // Python interpreter
    "/usr/bin/rsync",
    "/usr/bin/tar",
    "/usr/bin/gzip",
    "/usr/bin/zip",
    "/usr/bin/unzip",
    NULL
};

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

// Load whitelist from configuration file
static bool load_whitelist_config(const char *config_file) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        return false;
    }
    
    char line[MAX_PATH_LENGTH];
    
    while (fgets(line, sizeof(line), file) && whitelist_count < MAX_WHITELIST_ENTRIES) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        
        // Add to whitelist
        strncpy(whitelist[whitelist_count].pattern, line, MAX_PATH_LENGTH - 1);
        whitelist[whitelist_count].pattern[MAX_PATH_LENGTH - 1] = '\0';
        
        // Check if this is a prefix pattern (ends with /)
        whitelist[whitelist_count].is_prefix = (len > 0 && line[len - 1] == '/');
        
        whitelist_count++;
    }
    
    fclose(file);
    return true;
}

// Initialize whitelist
bool init_whitelist(const char *config_file) {
    pthread_mutex_lock(&whitelist_mutex);
    
    if (whitelist != NULL) {
        free(whitelist);
    }
    
    whitelist = calloc(MAX_WHITELIST_ENTRIES, sizeof(whitelist_entry_t));
    if (whitelist == NULL) {
        pthread_mutex_unlock(&whitelist_mutex);
        return false;
    }
    
    whitelist_count = 0;
    
    // Try to load from config file if specified
    if (config_file != NULL) {
        if (load_whitelist_config(config_file)) {
            pthread_mutex_unlock(&whitelist_mutex);
            return true;
        }
        // If config file loading fails, fall through to defaults
    }
    
    // Load default whitelist
    for (int i = 0; default_whitelist[i] != NULL && whitelist_count < MAX_WHITELIST_ENTRIES; i++) {
        strncpy(whitelist[whitelist_count].pattern, default_whitelist[i], MAX_PATH_LENGTH - 1);
        whitelist[whitelist_count].pattern[MAX_PATH_LENGTH - 1] = '\0';
        
        // Check if this is a prefix pattern (ends with /)
        size_t len = strlen(default_whitelist[i]);
        whitelist[whitelist_count].is_prefix = (len > 0 && default_whitelist[i][len - 1] == '/');
        
        whitelist_count++;
    }
    
    pthread_mutex_unlock(&whitelist_mutex);
    return true;
}

// Check if a process is whitelisted
bool is_process_whitelisted(pid_t pid, const char *exec_path) {
    char path_buffer[MAX_PATH_LENGTH];
    const char *path_to_check;
    
    // If exec_path is NULL or empty, get it from pid
    if (exec_path == NULL || exec_path[0] == '\0') {
        if (!get_exe_path(pid, path_buffer, sizeof(path_buffer))) {
            return false;
        }
        path_to_check = path_buffer;
    } else {
        path_to_check = exec_path;
    }
    
    pthread_mutex_lock(&whitelist_mutex);
    
    // Check against whitelist entries
    for (int i = 0; i < whitelist_count; i++) {
        if (whitelist[i].is_prefix) {
            // Prefix match
            size_t prefix_len = strlen(whitelist[i].pattern);
            if (strncmp(path_to_check, whitelist[i].pattern, prefix_len) == 0) {
                pthread_mutex_unlock(&whitelist_mutex);
                return true;
            }
        } else {
            // Exact match
            if (strcmp(path_to_check, whitelist[i].pattern) == 0) {
                pthread_mutex_unlock(&whitelist_mutex);
                return true;
            }
        }
    }
    
    pthread_mutex_unlock(&whitelist_mutex);
    return false;
}

// Add a process or path pattern to the whitelist
bool add_to_whitelist(const char *pattern) {
    if (pattern == NULL || pattern[0] == '\0') {
        return false;
    }
    
    pthread_mutex_lock(&whitelist_mutex);
    
    if (whitelist_count >= MAX_WHITELIST_ENTRIES) {
        pthread_mutex_unlock(&whitelist_mutex);
        return false;
    }
    
    strncpy(whitelist[whitelist_count].pattern, pattern, MAX_PATH_LENGTH - 1);
    whitelist[whitelist_count].pattern[MAX_PATH_LENGTH - 1] = '\0';
    
    // Check if this is a prefix pattern (ends with /)
    size_t len = strlen(pattern);
    whitelist[whitelist_count].is_prefix = (len > 0 && pattern[len - 1] == '/');
    
    whitelist_count++;
    
    pthread_mutex_unlock(&whitelist_mutex);
    return true;
}

// Clean up whitelist resources
void cleanup_whitelist(void) {
    pthread_mutex_lock(&whitelist_mutex);
    
    if (whitelist != NULL) {
        free(whitelist);
        whitelist = NULL;
    }
    
    whitelist_count = 0;
    
    pthread_mutex_unlock(&whitelist_mutex);
}