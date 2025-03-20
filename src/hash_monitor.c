// hash_monitor.c
#include "common_defs.h"
#include "hash_monitor.h"
#include "entropy_analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <time.h>
#include <unistd.h>   // For close, sleep
#include "logger.h"   // For log_suspicious_activity

#define MAX_TRACKED_PIDS 256
#define SOCKET_EVENTS_PER_PID 16
#define NETWORK_FILE_WINDOW 10  // 10 seconds 
#define ACTIVITY_TRACKING_WINDOW 30  // 30 seconds 
#define SUSPICIOUS_SOCKET_THRESHOLD 3  

typedef struct {
    char path[PATH_MAX];
    unsigned char hash[HASH_SIZE];
    double entropy;
    time_t last_check;
    bool valid;
} file_hash_t;

typedef struct {
    time_t timestamp;
    int socket_type;       
    int socket_family;     
    bool encrypted;        
} socket_event_t;

typedef struct {
    time_t timestamp;
    char path[PATH_MAX];
    bool high_entropy;     
} file_event_t;

typedef struct {
    pid_t pid;
    char process_name[256];
    time_t first_activity;
    time_t last_activity;
    
    int socket_count;
    int current_socket_idx;
    socket_event_t socket_events[SOCKET_EVENTS_PER_PID];
    
    int file_count;
    int current_file_idx;
    file_event_t file_events[SOCKET_EVENTS_PER_PID];
    
    bool has_network_activity;
    bool has_file_activity;
    bool suspicious_pattern;
    bool reported;
    int suspicion_score;
} network_file_tracker_t;

static file_hash_t *tracked_hashes = NULL;
static int max_tracked_files = 0;
static int file_count = 0;
static int suspicious_changes = 0;
static pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;
static network_file_tracker_t *network_file_trackers = NULL;
static int tracker_count = 0;
static pthread_mutex_t tracker_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool netlink_monitoring_active = false;
static pthread_t netlink_thread;

static bool calculate_file_hash(const char *path, unsigned char *hash) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        return false;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        return false;
    }
    
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return false;
    }
    
    unsigned char buffer[4096];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (1 != EVP_DigestUpdate(mdctx, buffer, bytes_read)) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return false;
        }
    }
    
    unsigned int digest_len;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &digest_len)) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return false;
    }
    
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    
    return true;
}

static double hash_similarity(const unsigned char *hash1, const unsigned char *hash2) {
    int matching_bits = 0;
    
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned char xor_result = hash1[i] ^ hash2[i];
        
        for (int bit = 0; bit < 8; bit++) {
            if ((xor_result & (1 << bit)) == 0) {
                matching_bits++;
            }
        }
    }
    
    return matching_bits / (double)(HASH_SIZE * 8);
}

bool init_hash_monitor(int max_files) {
    pthread_mutex_lock(&hash_mutex);
    
    if (tracked_hashes != NULL) {
        free(tracked_hashes);
    }
    
    max_tracked_files = max_files > 0 ? max_files : 1000;
    tracked_hashes = calloc(max_tracked_files, sizeof(file_hash_t));
    if (tracked_hashes == NULL) {
        pthread_mutex_unlock(&hash_mutex);
        return false;
    }
    
    file_count = 0;
    suspicious_changes = 0;
    
    pthread_mutex_unlock(&hash_mutex);
    
    if (!init_network_file_tracking()) {
        return false;
    }
    
    if (!start_netlink_monitoring()) {
        // Non-fatal error, we'll still track manually reported events
        log_suspicious_activity("Warning: Failed to start netlink monitoring for socket events");
    }
    
    return true;
}

bool monitor_file_hash(const char *path) {
    if (path == NULL) {
        return false;
    }
    
    pthread_mutex_lock(&hash_mutex);
    
    for (int i = 0; i < file_count; i++) {
        if (strcmp(tracked_hashes[i].path, path) == 0) {
            pthread_mutex_unlock(&hash_mutex);
            return true;
        }
    }
    
    if (file_count >= max_tracked_files) {
        pthread_mutex_unlock(&hash_mutex);
        return false;
    }
    
    file_hash_t *entry = &tracked_hashes[file_count];
    strncpy(entry->path, path, PATH_MAX - 1);
    entry->path[PATH_MAX - 1] = '\0';
    
    if (!calculate_file_hash(path, entry->hash)) {
        pthread_mutex_unlock(&hash_mutex);
        return false;
    }
    
    entry->entropy = calculate_file_entropy(path);
    entry->last_check = time(NULL);
    entry->valid = true;
    
    file_count++;
    
    pthread_mutex_unlock(&hash_mutex);
    return true;
}

bool check_file_changed(const char *path, hash_change_event_t *event) {
    if (path == NULL) {
        return false;
    }
    
    pthread_mutex_lock(&hash_mutex);
    
    int index = -1;
    for (int i = 0; i < file_count; i++) {
        if (strcmp(tracked_hashes[i].path, path) == 0) {
            index = i;
            break;
        }
    }
    
    if (index == -1) {
        pthread_mutex_unlock(&hash_mutex);
        return false;
    }
    
    file_hash_t *entry = &tracked_hashes[index];
    unsigned char new_hash[HASH_SIZE];
    
    if (!calculate_file_hash(path, new_hash)) {
        pthread_mutex_unlock(&hash_mutex);
        return false;
    }
    
    double new_entropy = calculate_file_entropy(path);
    double entropy_change = new_entropy - entry->entropy;
    
    double similarity = hash_similarity(entry->hash, new_hash);
    bool significant_change = similarity < 0.9;  
    
    bool entropy_increased = entropy_change > 0.3;  
    
    bool suspicious = significant_change && entropy_increased;
    
    if (event != NULL) {
        strncpy(event->path, path, PATH_MAX - 1);
        event->path[PATH_MAX - 1] = '\0';
        memcpy(event->original_hash, entry->hash, HASH_SIZE);
        memcpy(event->new_hash, new_hash, HASH_SIZE);
        event->similarity = similarity;
        event->entropy_change = entropy_change;
    }
    
    if (significant_change) {
        memcpy(entry->hash, new_hash, HASH_SIZE);
        entry->entropy = new_entropy;
        entry->last_check = time(NULL);
        
        if (suspicious) {
            suspicious_changes++;
        }
    }
    
    pthread_mutex_unlock(&hash_mutex);
    return suspicious;
}

int get_suspicious_hash_change_count(void) {
    return suspicious_changes;
}

void cleanup_hash_monitor(void) {
    pthread_mutex_lock(&hash_mutex);
    
    if (tracked_hashes != NULL) {
        free(tracked_hashes);
        tracked_hashes = NULL;
    }
    
    file_count = 0;
    suspicious_changes = 0;
    
    pthread_mutex_unlock(&hash_mutex);
    
    cleanup_network_file_tracking();
}

bool init_network_file_tracking(void) {
    pthread_mutex_lock(&tracker_mutex);
    
    if (network_file_trackers != NULL) {
        free(network_file_trackers);
    }
    
    network_file_trackers = calloc(MAX_TRACKED_PIDS, sizeof(network_file_tracker_t));
    if (network_file_trackers == NULL) {
        pthread_mutex_unlock(&tracker_mutex);
        return false;
    }
    
    tracker_count = 0;
    pthread_mutex_unlock(&tracker_mutex);
    
    return true;
}

static void get_process_name(pid_t pid, char *name, size_t name_len) {
    if (!name || name_len == 0) {
        return;
    }
    
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", pid);
    
    FILE *comm_file = fopen(proc_path, "r");
    if (comm_file) {
        if (fgets(name, name_len, comm_file)) {
            size_t len = strlen(name);
            if (len > 0 && name[len-1] == '\n') {
                name[len-1] = '\0';
            }
        } else {
            strncpy(name, "unknown", name_len - 1);
            name[name_len - 1] = '\0';
        }
        fclose(comm_file);
    } else {
        strncpy(name, "unknown", name_len - 1);
        name[name_len - 1] = '\0';
    }
}

static network_file_tracker_t *find_network_file_tracker(pid_t pid) {
    pthread_mutex_lock(&tracker_mutex);
    
    for (int i = 0; i < tracker_count; i++) {
        if (network_file_trackers[i].pid == pid) {
            pthread_mutex_unlock(&tracker_mutex);
            return &network_file_trackers[i];
        }
    }
    
    if (tracker_count < MAX_TRACKED_PIDS) {
        network_file_tracker_t *tracker = &network_file_trackers[tracker_count++];
        memset(tracker, 0, sizeof(network_file_tracker_t));
        tracker->pid = pid;
        time_t now = time(NULL);
        tracker->first_activity = now;
        tracker->last_activity = now;
        get_process_name(pid, tracker->process_name, sizeof(tracker->process_name));
        
        pthread_mutex_unlock(&tracker_mutex);
        return tracker;
    }
    
    time_t oldest_time = time(NULL);
    int oldest_idx = 0;
    
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (network_file_trackers[i].last_activity < oldest_time) {
            oldest_time = network_file_trackers[i].last_activity;
            oldest_idx = i;
        }
    }
    
    network_file_tracker_t *tracker = &network_file_trackers[oldest_idx];
    memset(tracker, 0, sizeof(network_file_tracker_t));
    tracker->pid = pid;
    time_t now = time(NULL);
    tracker->first_activity = now;
    tracker->last_activity = now;
    get_process_name(pid, tracker->process_name, sizeof(tracker->process_name));
    
    pthread_mutex_unlock(&tracker_mutex);
    return tracker;
}

static int calculate_network_file_suspicion(network_file_tracker_t *tracker) {
    time_t now = time(NULL);
    
    // Reset if window expired
    if (now - tracker->first_activity > ACTIVITY_TRACKING_WINDOW) {
        tracker->first_activity = now;
        tracker->socket_count = 0;
        tracker->file_count = 0;
        tracker->suspicious_pattern = false;
        tracker->reported = false;
        return 0;
    }
    
    if (!tracker->has_network_activity || !tracker->has_file_activity) {
        return 0;
    }
    
    int suspicion = 0;
    
    if (tracker->socket_count > SUSPICIOUS_SOCKET_THRESHOLD) {
        suspicion += 40;  
    }
    
    bool close_correlation = false;
    
    // Compare socket event with file events to correlations
    for (int i = 0; i < min(tracker->socket_count, SOCKET_EVENTS_PER_PID); i++) {
        int socket_idx = (tracker->current_socket_idx - i - 1 + SOCKET_EVENTS_PER_PID) % SOCKET_EVENTS_PER_PID;
        socket_event_t *socket_event = &tracker->socket_events[socket_idx];
        
        for (int j = 0; j < min(tracker->file_count, SOCKET_EVENTS_PER_PID); j++) {
            int file_idx = (tracker->current_file_idx - j - 1 + SOCKET_EVENTS_PER_PID) % SOCKET_EVENTS_PER_PID;
            file_event_t *file_event = &tracker->file_events[file_idx];
            
            time_t time_diff = labs(socket_event->timestamp - file_event->timestamp);
            
            if (time_diff <= NETWORK_FILE_WINDOW) {
                close_correlation = true;
                
                if (file_event->high_entropy && file_event->timestamp >= socket_event->timestamp) {
                    suspicion += 30;
                } else {
                    suspicion += 20;
                }
                
                if (socket_event->encrypted) {
                    suspicion += 10;
                }
            }
        }
    }
    
    if (close_correlation) {
        suspicion += 20;
    }
    
    if (suspicion > 100) {
        suspicion = 100;
    }
    
    return suspicion;
}

static void report_suspicious_network_file_activity(network_file_tracker_t *tracker) {
    if (tracker->reported) {
        return;
    }
    
    tracker->reported = true;
    
    char message[1024];
    snprintf(message, sizeof(message),
            "[WARNING] Process %d (%s) shows correlated network and file activity: "
            "%d socket(s), %d file(s) modified, suspicion score: %d",
            tracker->pid, tracker->process_name, tracker->socket_count, 
            tracker->file_count, tracker->suspicion_score);
    
    log_suspicious_activity(message);
    
    if (tracker->socket_count > 0) {
        int recent_socket_idx = (tracker->current_socket_idx - 1 + SOCKET_EVENTS_PER_PID) % SOCKET_EVENTS_PER_PID;
        socket_event_t *recent_socket = &tracker->socket_events[recent_socket_idx];
        
        char socket_info[256];
        snprintf(socket_info, sizeof(socket_info),
                "Recent socket: family=%d, type=%d, %s",
                recent_socket->socket_family, recent_socket->socket_type,
                recent_socket->encrypted ? "encrypted" : "unencrypted");
        log_suspicious_activity(socket_info);
    }
    
    if (tracker->file_count > 0) {
        int recent_file_idx = (tracker->current_file_idx - 1 + SOCKET_EVENTS_PER_PID) % SOCKET_EVENTS_PER_PID;
        file_event_t *recent_file = &tracker->file_events[recent_file_idx];
        
        char file_info[PATH_MAX + 64];
        snprintf(file_info, sizeof(file_info),
                "Recent file modified: %s (high entropy: %s)",
                recent_file->path, recent_file->high_entropy ? "YES" : "no");
        log_suspicious_activity(file_info);
    }
    
    score_network_file_activity(tracker->pid, tracker->suspicion_score);
}

static bool is_likely_encrypted_socket(int family, int port) {
    const int encrypted_ports[] = {
        443,    // HTTPS
        993,    // IMAPS
        995,    // POP3S
        465,    // SMTPS
        636,    // LDAPS
        989,    // FTPS data
        990,    // FTPS control
        5061,   // SIPS
        8883,   // MQTT over TLS
        6514,   // Syslog over TLS
        8443    // Alternative HTTPS
    };
    
    // Only check for IPv4/IPv6
    if (family != AF_INET && family != AF_INET6) {
        return false;
    }
    
    for (size_t i = 0; i < sizeof(encrypted_ports) / sizeof(encrypted_ports[0]); i++) {
        if (port == encrypted_ports[i]) {
            return true;
        }
    }
    
    return false;
}

void track_socket_event(pid_t pid, int socket_family, int socket_type, int port) {
    if (pid <= 0) {
        return;
    }
    
    network_file_tracker_t *tracker = find_network_file_tracker(pid);
    if (!tracker) {
        return;
    }
    
    time_t now = time(NULL);
    tracker->last_activity = now;
    tracker->has_network_activity = true;
    
    int idx = tracker->current_socket_idx;
    tracker->socket_events[idx].timestamp = now;
    tracker->socket_events[idx].socket_family = socket_family;
    tracker->socket_events[idx].socket_type = socket_type;
    tracker->socket_events[idx].encrypted = is_likely_encrypted_socket(socket_family, port);
    
    tracker->current_socket_idx = (tracker->current_socket_idx + 1) % SOCKET_EVENTS_PER_PID;
    tracker->socket_count++;
    
    tracker->suspicion_score = calculate_network_file_suspicion(tracker);
    tracker->suspicious_pattern = tracker->suspicion_score >= 70;
    
    if (tracker->suspicious_pattern) {
        report_suspicious_network_file_activity(tracker);
    }
}

void track_file_event(pid_t pid, const char *path, double entropy) {
    if (pid <= 0 || !path) {
        return;
    }
    
    network_file_tracker_t *tracker = find_network_file_tracker(pid);
    if (!tracker) {
        return;
    }
    
    time_t now = time(NULL);
    tracker->last_activity = now;
    tracker->has_file_activity = true;
    
    int idx = tracker->current_file_idx;
    tracker->file_events[idx].timestamp = now;
    strncpy(tracker->file_events[idx].path, path, PATH_MAX - 1);
    tracker->file_events[idx].path[PATH_MAX - 1] = '\0';
    tracker->file_events[idx].high_entropy = entropy >= 0.7;
    
    tracker->current_file_idx = (tracker->current_file_idx + 1) % SOCKET_EVENTS_PER_PID;
    tracker->file_count++;
    
    tracker->suspicion_score = calculate_network_file_suspicion(tracker);
    tracker->suspicious_pattern = tracker->suspicion_score >= 70;
    
    if (tracker->suspicious_pattern) {
        report_suspicious_network_file_activity(tracker);
    }
}

void *netlink_monitoring_thread(void *arg) {
    // Mark arg as used to avoid the warning
    (void)arg;  // Suppress unused parameter warning
    
    int sock_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG);
    if (sock_fd < 0) {
        perror("Failed to create netlink socket");
        return NULL;
    }
    
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    
    if (bind(sock_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Failed to bind netlink socket");
        close(sock_fd);
        return NULL;
    }
    
    while (netlink_monitoring_active) {
        // TODO: Implement socket monitoring
        // we'd use netlink to monitor socket creation
        
        // For now, we'll just sleep to prevent high CPU usage
        sleep(1);
    }
    
    close(sock_fd);
    return NULL;
}

bool start_netlink_monitoring(void) {
    if (netlink_monitoring_active) {
        return true;  // Already running
    }
    
    netlink_monitoring_active = true;
    
    int result = pthread_create(&netlink_thread, NULL, netlink_monitoring_thread, NULL);
    if (result != 0) {
        netlink_monitoring_active = false;
        return false;
    }
    
    return true;
}

void stop_netlink_monitoring(void) {
    if (!netlink_monitoring_active) {
        return;  // Not running
    }
    
    netlink_monitoring_active = false;
    pthread_join(netlink_thread, NULL);
}

// static void track_network_and_file_activity(pid_t pid, const char *file_path, double entropy) {
//     if (pid <= 0) {
//         return;
//     }
//     
//     static bool initialized = false;
//     if (!initialized) {
//         if (!init_network_file_tracking()) {
//             return;
//         }
//         initialized = true;
//     }
//     
//     switch (event_type) {
//         case TRACK_SOCKET:
//             track_socket_event(pid, socket_family, socket_type, port);
//             break;
//             
//         case TRACK_FILE:
//             if (path) {
//                 track_file_event(pid, path, entropy);
//             }
//             break;
//             
//         default:
//             return;
//     }
//     
//     network_file_tracker_t *tracker = find_network_file_tracker(pid);
//     if (!tracker) {
//         return;
//     }
//     
//     return tracker->suspicious_pattern;
// }

void cleanup_network_file_tracking(void) {
    if (netlink_monitoring_active) {
        stop_netlink_monitoring();
    }
    
    pthread_mutex_lock(&tracker_mutex);
    
    if (network_file_trackers != NULL) {
        free(network_file_trackers);
        network_file_trackers = NULL;
    }
    
    tracker_count = 0;
    
    pthread_mutex_unlock(&tracker_mutex);
}

void get_network_file_stats(network_file_stats_t *stats) {
    if (!stats) {
        return;
    }
    
    memset(stats, 0, sizeof(network_file_stats_t));
    
    pthread_mutex_lock(&tracker_mutex);
    
    stats->tracked_processes = tracker_count;
    
    for (int i = 0; i < tracker_count; i++) {
        if (network_file_trackers[i].suspicious_pattern) {
            stats->suspicious_processes++;
        }
        
        if (network_file_trackers[i].has_network_activity) {
            stats->processes_with_network++;
        }
        
        if (network_file_trackers[i].has_file_activity) {
            stats->processes_with_files++;
        }
        
        if (network_file_trackers[i].has_network_activity && network_file_trackers[i].has_file_activity) {
            stats->processes_with_both++;
        }
    }
    
    pthread_mutex_unlock(&tracker_mutex);
}