/**
 * activity_scorer.h - Scores file activities to identify suspicious patterns
 */

#ifndef ACTIVITY_SCORER_H
#define ACTIVITY_SCORER_H

#include <stdbool.h>
#include <sys/types.h>

// Types of operations to score
typedef enum {
    SCORE_FILE_CREATE,
    SCORE_FILE_MODIFY,
    SCORE_FILE_DELETE,
    SCORE_FILE_RENAME
} score_operation_t;

// Score levels
typedef enum {
    RISK_LEVEL_NONE = 0,
    RISK_LEVEL_LOW = 1,
    RISK_LEVEL_MEDIUM = 2,
    RISK_LEVEL_HIGH = 3,
    RISK_LEVEL_CRITICAL = 4
} risk_level_t;

// Initialize the activity scorer
bool init_activity_scorer(void);

/**
 * Score a file operation
 * @param pid Process ID performing the operation
 * @param operation Type of operation
 * @param path Path to the file being operated on
 * @param entropy File entropy after operation (or -1 if not available)
 * @return Risk level of this activity
 */
risk_level_t score_file_activity(pid_t pid, score_operation_t operation, const char *path, double entropy);

/**
 * Get the cumulative risk score for a process
 * @param pid Process ID to check
 * @return Risk level for this process
 */
risk_level_t get_process_risk_level(pid_t pid);

/**
 * Reset scores for a process
 * @param pid Process ID to reset
 */
void reset_process_scores(pid_t pid);

/**
 * Clean up resources
 */
void cleanup_activity_scorer(void);

#endif /* ACTIVITY_SCORER_H */