// behavioral_analysis.h

#ifndef BEHAVIORAL_ANALYSIS_H
#define BEHAVIORAL_ANALYSIS_H

#include <stdbool.h>
#include <limits.h>

typedef enum {
    FILE_OP_READ,
    FILE_OP_WRITE,
    FILE_OP_CREATE,
    FILE_OP_DELETE,
    FILE_OP_RENAME
} file_op_type_t;

typedef enum {
    REASON_HIGH_FREQUENCY,
    REASON_HIGH_FREQUENCY_AND_ENTROPY,
    REASON_WRITE_THEN_DELETE,
    REASON_SUSPICIOUS_PATTERN
} suspicious_reason_t;

typedef struct {
    char path[PATH_MAX];
    int operation_count;
    double entropy;
    suspicious_reason_t reason;
} suspicious_activity_t;

/**
 * Initialize the behavioral analysis system
 * @param max_files Maximum number of files to track
 * @param ops_threshold Operations per minute threshold
 * @param ent_threshold Entropy threshold (0.0-1.0)
 * @return true on success, false on failure
 */
bool init_behavioral_analysis(int max_files, int ops_threshold, double ent_threshold);

/**
 * Record a file operation
 * @param path Path to the file
 * @param op_type Type of operation
 * @param entropy Entropy of the file content (0.0-1.0)
 */
void record_file_operation(const char *path, file_op_type_t op_type, double entropy);

/**
 * Check for suspicious activity
 * @param result Structure to fill with detection results
 * @return true if suspicious activity was detected
 */
bool detect_suspicious_activity(suspicious_activity_t *result);

void cleanup_behavioral_analysis(void);

#endif 