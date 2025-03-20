// activity_scorer.h - Scores file activities to identify suspicious patterns

#ifndef ACTIVITY_SCORER_H
#define ACTIVITY_SCORER_H

#include <stdbool.h>
#include <sys/types.h>
#include "common_defs.h"  // Include first for shared definitions

// Risk level enum
typedef enum {
    RISK_LEVEL_NONE = 0,
    RISK_LEVEL_LOW = 1,
    RISK_LEVEL_MEDIUM = 2,
    RISK_LEVEL_HIGH = 3,
    RISK_LEVEL_CRITICAL = 4
} risk_level_t;

// Score operation type
typedef enum {
    SCORE_FILE_CREATE,
    SCORE_FILE_MODIFY,
    SCORE_FILE_DELETE,
    SCORE_FILE_RENAME
} score_operation_t;

// Score constants - make sure these don't conflict with duplicates in C files
#define SCORE_MEMORY_INJECTION     1001
#define SCORE_MEMORY_PROTECTION    1002
#define SCORE_MEMORY_MAPPING       1003

// Function declarations
bool init_activity_scorer(void);
risk_level_t score_file_activity(pid_t pid, score_operation_t operation, const char *path, double entropy);
risk_level_t get_process_risk_level(pid_t pid);
void reset_process_scores(pid_t pid);
void cleanup_activity_scorer(void);
void update_alert_threshold(void);
int score_syscall_event(pid_t pid, int event_type, const char *path, double entropy);
int calculate_score(pid_t pid, scoring_factors_t *factors);
int score_detailed_event(pid_t pid, scoring_factors_t *factors);
void log_suspicious_activity(const char *message);

#endif /* ACTIVITY_SCORER_H */