// hash_monitor.h

#ifndef HASH_MONITOR_H
#define HASH_MONITOR_H

#include <stdbool.h>
#include <sys/types.h>
#include <limits.h>
#include "common_defs.h"  // Include first for shared definitions

#define HASH_SIZE 32  // SHA-256 hash size

// Function declarations
bool init_hash_monitor(int max_files);
bool monitor_file_hash(const char *path);
bool check_file_changed(const char *path, hash_change_event_t *event);
int get_suspicious_hash_change_count(void);
void cleanup_hash_monitor(void);

// Network tracking
bool init_network_file_tracking(void);
void track_socket_event(pid_t pid, int socket_family, int socket_type, int port);
void track_file_event(pid_t pid, const char *path, double entropy);
void cleanup_network_file_tracking(void);
void get_network_file_stats(network_file_stats_t *stats);
bool start_netlink_monitoring(void);
void stop_netlink_monitoring(void);

#endif /* HASH_MONITOR_H */