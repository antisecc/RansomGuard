// activity_scorer.h - Scores file activities to identify suspicious patterns


#ifndef ACTIVITY_SCORER_H
#define ACTIVITY_SCORER_H

#include <stdbool.h>
#include <sys/types.h>

typedef enum {
    SCORE_FILE_CREATE,
    SCORE_FILE_MODIFY,
    SCORE_FILE_DELETE,
    SCORE_FILE_RENAME
} score_operation_t;

typedef enum {
    RISK_LEVEL_NONE = 0,
    RISK_LEVEL_LOW = 1,
    RISK_LEVEL_MEDIUM = 2,
    RISK_LEVEL_HIGH = 3,
    RISK_LEVEL_CRITICAL = 4
} risk_level_t;

bool init_activity_scorer(void);

risk_level_t score_file_activity(pid_t pid, score_operation_t operation, const char *path, double entropy);

risk_level_t get_process_risk_level(pid_t pid);

void reset_process_scores(pid_t pid);

void cleanup_activity_scorer(void);

void update_alert_threshold(void);

int score_syscall_event(pid_t pid, int event_type, const char *path, double entropy);

int score_network_file_activity(pid_t pid, int suspicion_score);

typedef struct {
    double entropy;                
    bool suspicious_parent_child;   
    bool high_frequency;           
    bool rwx_permission;           
    bool network_correlation;      
    bool memory_injection;         
    bool unusual_time;              
    int affected_processes;         
    bool hidden_file;              
    char *paths[5];                 
    int path_count;                 
} scoring_factors_t;

int score_detailed_event(pid_t pid, scoring_factors_t *factors);

#define SCORE_MEMORY_INJECTION     1001
#define SCORE_MEMORY_PROTECTION    1002
#define SCORE_MEMORY_MAPPING       1003

#endif 