// behavioral_analysis.h

#ifndef BEHAVIORAL_ANALYSIS_H
#define BEHAVIORAL_ANALYSIS_H

#include <stdbool.h>
#include <sys/types.h>
#include <limits.h>
#include "common_defs.h"  // Include first for shared definitions

typedef struct {
    bool suspicious;
    double confidence;
    pid_t pid;
    char process_name[256];
    int operation_count;
    int reason;  // Use the REASON_* constants from common_defs.h
    
    // Add these fields that are being referenced:
    char path[PATH_MAX];
    double entropy;
} suspicious_activity_t;

// Update function declaration to match implementation
bool init_behavioral_analysis(int max_files, int ops_threshold, double ent_threshold);
void cleanup_behavioral_analysis(void);
void record_file_operation(const char *path, file_op_type_t op_type, double entropy);
bool detect_suspicious_activity(suspicious_activity_t *result);
bool analyze_file_operations(const char *path, double *entropy_result);

#endif /* BEHAVIORAL_ANALYSIS_H */