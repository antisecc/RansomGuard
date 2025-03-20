// logger.c - Implementation of logging functions

#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>

#define MAX_LOG_LINE 1024
#define DEFAULT_LOG_PATH "/var/log/ransomguard.log"

static FILE *log_file = NULL;
static int verbosity = 0;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool console_logging = true;

bool init_logger(int verbosity_level) {
    pthread_mutex_lock(&log_mutex);
    
    verbosity = verbosity_level;
    
    // Try to open log file in /var/log first
    const char *log_path = DEFAULT_LOG_PATH;
    log_file = fopen(log_path, "a");
    
    // If can't open the default path, try in current directory
    if (!log_file) {
        log_path = "ransomguard.log";
        log_file = fopen(log_path, "a");
    }
    
    pthread_mutex_unlock(&log_mutex);
    
    if (!log_file) {
        perror("Could not open log file");
        return false;
    }
    
    // Set buffer to line buffering
    setvbuf(log_file, NULL, _IOLBF, 0);
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);
    
    fprintf(log_file, "\n[%s] RansomGuard logger initialized (verbosity=%d)\n", 
            timestamp, verbosity);
    
    if (console_logging) {
        printf("Logging initialized (file: %s, verbosity=%d)\n", log_path, verbosity);
    }
    
    return true;
}

void log_message(log_level_t level, const char *message) {
    if (!message) return;
    
    // Skip messages if below verbosity level
    if ((int)level < verbosity) return;
    
    pthread_mutex_lock(&log_mutex);
    
    if (!log_file) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);
    
    const char *level_str = "UNKNOWN";
    switch (level) {
        case LOG_LEVEL_DEBUG:    level_str = "DEBUG"; break;
        case LOG_LEVEL_INFO:     level_str = "INFO"; break;
        case LOG_LEVEL_WARNING:  level_str = "WARNING"; break;
        case LOG_LEVEL_ERROR:    level_str = "ERROR"; break;
        case LOG_LEVEL_CRITICAL: level_str = "CRITICAL"; break;
    }
    
    fprintf(log_file, "[%s] [%s] %s\n", timestamp, level_str, message);
    
    if (console_logging && level >= LOG_LEVEL_WARNING) {
        printf("[%s] %s\n", level_str, message);
    }
    
    pthread_mutex_unlock(&log_mutex);
}

void log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    if (log_file) {
        fprintf(log_file, "[%s] [ERROR] ", timestamp);
        vfprintf(log_file, format, args);
        fprintf(log_file, "\n");
        fflush(log_file);
    }
    
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    
    va_end(args);
}

void log_warning(const char *message) {
    log_message(LOG_LEVEL_WARNING, message);
}

void log_suspicious_activity(const char *message) {
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    if (log_file) {
        fprintf(log_file, "[%s] [ALERT] %s\n", timestamp, message);
        fflush(log_file);
    }
    
    fprintf(stderr, "[ALERT] %s\n", message);
}

void cleanup_logger(void) {
    pthread_mutex_lock(&log_mutex);
    
    if (log_file) {
        fprintf(log_file, "\n---- RansomGuard logger closed ----\n");
        fclose(log_file);
        log_file = NULL;
    }
    
    pthread_mutex_unlock(&log_mutex);
}

