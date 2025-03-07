// behavioral_analysis.h
 
#ifndef BEHAVIORAL_ANALYSIS_H
#define BEHAVIORAL_ANALYSIS_H
 
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
 
#define MAX_PATH 1024
#define FILE_HISTORY_SIZE 10
#define MAX_TRACKED_FILES 1000
 
typedef enum {
    FILE_OP_OPEN,
    FILE_OP_WRITE,
    FILE_OP_CLOSE,
    FILE_OP_RENAME,
    FILE_OP_DELETE,
    FILE_OP_CHMOD
} file_operation_t;
 
typedef struct {
    char filename[MAX_PATH];
    struct {
        file_operation_t operation;
        time_t timestamp;
    } history[FILE_HISTORY_SIZE];
    int history_index;
    unsigned int entropy;
    time_t first_seen;
} file_activity_t;
 
bool init_behavioral_analysis(void);
void track_file_operation(const char *filename, file_operation_t operation, pid_t pid);
bool detect_suspicious_patterns(pid_t pid);
unsigned int calculate_file_entropy(const char *filename);
void cleanup_behavioral_analysis(void);
 
#endif