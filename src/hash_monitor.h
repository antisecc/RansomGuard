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
    double similarity;  
    double entropy_change;  
} hash_change_event_t;

bool init_hash_monitor(int max_files);

bool monitor_file_hash(const char *path);

bool check_file_changed(const char *path, hash_change_event_t *event);

int get_suspicious_hash_change_count(void);

void cleanup_hash_monitor(void);

#define TRACK_SOCKET 1
#define TRACK_FILE 2

typedef struct {
    int tracked_processes;       
    int suspicious_processes;    
    int processes_with_network;  
    int processes_with_files;    
    int processes_with_both;     
} network_file_stats_t;

void score_network_file_activity(pid_t pid, int suspicion_score);

bool init_network_file_tracking(void);

void track_socket_event(pid_t pid, int socket_family, int socket_type, int port);

void track_file_event(pid_t pid, const char *path, double entropy);

bool track_network_and_file_activity(pid_t pid, int event_type, const char *path, int socket_family, int socket_type, int port, double entropy);

void cleanup_network_file_tracking(void);

void get_network_file_stats(network_file_stats_t *stats);

#endif