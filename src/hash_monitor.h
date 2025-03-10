// hash_monitor.h

#ifndef HASH_MONITOR_H
#define HASH_MONITOR_H

#include <stdbool.h>
#include <limits.h>

#define HASH_SIZE 32  // SHA-256 hash size

typedef struct {
    char path[PATH_MAX];
    unsigned char original_hash[HASH_SIZE];
    unsigned char new_hash[HASH_SIZE];
    double similarity;  // 0.0 - 1.0 (higher = more similar)
    double entropy_change;  // Positive = increased entropy
} hash_change_event_t;

/**
 * Initialize hash monitoring
 * @param max_files Maximum number of files to track
 * @return true on success, false on failure
 */
bool init_hash_monitor(int max_files);

/**
 * Start monitoring a file for hash changes
 * @param path Path to the file
 * @return true if the file was added for monitoring
 */
bool monitor_file_hash(const char *path);

/**
 * Check if a file has been modified/encrypted
 * @param path Path to the file
 * @param event If not NULL, filled with change details
 * @return true if the file was changed significantly
 */
bool check_file_changed(const char *path, hash_change_event_t *event);

/**
 * Get the number of suspicious hash changes detected
 * @return Count of suspicious changes
 */
int get_suspicious_hash_change_count(void);

void cleanup_hash_monitor(void);

#endif 