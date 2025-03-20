// Create this new header file to centralize common definitions
#ifndef COMMON_DEFS_H
#define COMMON_DEFS_H

#include <stdbool.h>
#include <sys/types.h>
#include <limits.h>
#include <time.h>  // For time_t

// Common constants
#define TRACK_SOCKET 1
#define TRACK_FILE   2

// Define the file operation type enum (used by multiple files)
typedef enum {
    FILE_OP_CREATE,
    FILE_OP_WRITE,
    FILE_OP_DELETE,
    FILE_OP_RENAME,
    FILE_OP_CHMOD,
    FILE_OP_UNKNOWN
} file_op_type_t;

// Define the scoring_factors struct (used by multiple files)
typedef struct scoring_factors {
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

// Define hash_change_event struct
typedef struct hash_change_event {
    char path[PATH_MAX];
    unsigned char original_hash[32];  // SHA-256 size
    unsigned char new_hash[32];       // SHA-256 size
    double similarity;
    double entropy_change;
} hash_change_event_t;

// Define network_file_stats struct
typedef struct network_file_stats {
    int tracked_processes;       
    int suspicious_processes;    
    int processes_with_network;  
    int processes_with_files;    
    int processes_with_both;     
} network_file_stats_t;

// Define the suspicious activity reasons
#define REASON_HIGH_FREQUENCY 1
#define REASON_HIGH_FREQUENCY_AND_ENTROPY 2
#define REASON_WRITE_THEN_DELETE 3

// Common function declarations shared between modules
int score_network_file_activity(pid_t pid, int suspicion_score);
bool track_network_and_file_activity(pid_t pid, int event_type, const char *path,
                                   int socket_family, int socket_type, int port, double entropy);

// Utility functions used across modules
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

#endif /* COMMON_DEFS_H */