// file_monitor.c
#include "file_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <string.h>
#include <errno.h>  
#include "activity_scorer.h"
#include "entropy_analysis.h"
#include <dirent.h>
#include <time.h>
#include <sys/time.h>
#include <sys/sysinfo.h>
#include "logger.h"
#include "process_analyzer.h"
#include "common_defs.h"

// External dependencies
volatile int keep_running = 1; // Or declare extern if defined elsewhere

#define MAX_TRACKED_PIDS 128
#define EVENTS_PER_PID 64
#define FREQUENCY_WINDOW_SECONDS 10
#define SUSPICIOUS_MODIFICATION_THRESHOLD 5
#define DEFAULT_SCORE_THRESHOLD 20

typedef struct {
    uint64_t timestamp;    
    char path[PATH_MAX];   
    file_op_type_t op_type; 
} file_event_t;

typedef struct {
    pid_t pid;                         
    int event_count;                   
    int current_index;                 
    uint64_t last_check_time;          
    int recent_modifications;          
    bool reported;                     
    file_event_t events[EVENTS_PER_PID]; // Ring buffer of events
} pid_file_events_t;

static pid_file_events_t pid_file_events[MAX_TRACKED_PIDS];
static int pid_events_count = 0;

static int current_score_threshold = DEFAULT_SCORE_THRESHOLD;
static time_t last_threshold_check = 0;
static bool threshold_warning_logged = false;

static uint64_t get_monotonic_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

void init_file_modification_tracker() {
    memset(pid_file_events, 0, sizeof(pid_file_events));
    pid_events_count = 0;
}

static pid_file_events_t* find_pid_tracker(pid_t pid) {
    for (int i = 0; i < pid_events_count; i++) {
        if (pid_file_events[i].pid == pid) {
            return &pid_file_events[i];
        }
    }
    
    if (pid_events_count < MAX_TRACKED_PIDS) {
        pid_file_events_t *tracker = &pid_file_events[pid_events_count++];
        memset(tracker, 0, sizeof(pid_file_events_t));
        tracker->pid = pid;
        tracker->last_check_time = get_monotonic_time_ms();
        return tracker;
    }
    
    int oldest_idx = 0;
    uint64_t oldest_time = UINT64_MAX;
    
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        uint64_t last_event_time = 0;
        if (pid_file_events[i].event_count > 0) {
            int last_idx = (pid_file_events[i].current_index - 1) % EVENTS_PER_PID;
            if (last_idx < 0) last_idx += EVENTS_PER_PID;
            last_event_time = pid_file_events[i].events[last_idx].timestamp;
        }
        
        if (last_event_time < oldest_time) {
            oldest_time = last_event_time;
            oldest_idx = i;
        }
    }
    
    pid_file_events_t *tracker = &pid_file_events[oldest_idx];
    memset(tracker, 0, sizeof(pid_file_events_t));
    tracker->pid = pid;
    tracker->last_check_time = get_monotonic_time_ms();
    return tracker;
}

static bool check_child_processes(pid_t parent_pid, uint64_t current_time) {
    int total_child_mods = 0;
    
    for (int i = 0; i < pid_events_count; i++) {
        if (pid_file_events[i].pid == parent_pid) {
            continue;
        }
        
        pid_t ppid = get_parent_pid(pid_file_events[i].pid);
        
        if (ppid == parent_pid) {
            int child_mods = 0;
            
            for (int j = 0; j < pid_file_events[i].event_count && j < EVENTS_PER_PID; j++) {
                int event_idx = (pid_file_events[i].current_index - j - 1) % EVENTS_PER_PID;
                if (event_idx < 0) event_idx += EVENTS_PER_PID;
                
                file_event_t *event = &pid_file_events[i].events[event_idx];
                
                if (current_time - event->timestamp <= FREQUENCY_WINDOW_SECONDS * 1000) {
                    child_mods++;
                } else {
                    break;
                }
            }
            
            total_child_mods += child_mods;
            
            if (total_child_mods >= SUSPICIOUS_MODIFICATION_THRESHOLD) {
                return true;
            }
        }
    }
    
    return false;
}

bool track_file_modification_frequency(pid_t pid, const char *path, file_op_type_t op_type) {
    if (pid <= 0 || path == NULL) {
        return false;
    }
    
    uint64_t current_time = get_monotonic_time_ms();
    pid_file_events_t *tracker = find_pid_tracker(pid);
    
    if (!tracker) {
        return false; // Couldn't find or create tracker
    }
    
    // Add event to ring buffer
    int idx = tracker->current_index;
    tracker->events[idx].timestamp = current_time;
    strncpy(tracker->events[idx].path, path, PATH_MAX - 1);
    tracker->events[idx].path[PATH_MAX - 1] = '\0';
    tracker->events[idx].op_type = op_type;
    
    tracker->current_index = (tracker->current_index + 1) % EVENTS_PER_PID;
    if (tracker->event_count < EVENTS_PER_PID) {
        tracker->event_count++;
    }
    
    if (current_time - tracker->last_check_time < 500) { // 500ms
        return tracker->reported;
    }
    
    tracker->last_check_time = current_time;
    
    int modifications = 0;
    
    for (int i = 0; i < tracker->event_count; i++) {
        int event_idx = (tracker->current_index - i - 1) % EVENTS_PER_PID;
        if (event_idx < 0) event_idx += EVENTS_PER_PID;
        
        file_event_t *event = &tracker->events[event_idx];
        
        if (current_time - event->timestamp <= FREQUENCY_WINDOW_SECONDS * 1000) {
            modifications++;
        } else {
            break;
        }
    }
    
    tracker->recent_modifications = modifications;
    
    bool is_suspicious = (modifications >= SUSPICIOUS_MODIFICATION_THRESHOLD) || 
                        check_child_processes(pid, current_time);
    
    if (is_suspicious && !tracker->reported) {
        tracker->reported = true;
        return true;
    }
    
    if (!is_suspicious) {
        tracker->reported = false;
    }
    
    return false;
}

void get_frequency_report(pid_t pid, char *message, size_t message_size) {
    if (!message || message_size == 0) {
        return;
    }
    
    pid_file_events_t *tracker = NULL;
    for (int i = 0; i < pid_events_count; i++) {
        if (pid_file_events[i].pid == pid) {
            tracker = &pid_file_events[i];
            break;
        }
    }
    
    if (!tracker) {
        snprintf(message, message_size, "No file modification data for PID %d", pid);
        return;
    }
    
    char exe_path[PATH_MAX] = "unknown";
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
    }
    
    char *exe_name = strrchr(exe_path, '/');
    if (exe_name) {
        exe_name++; 
    } else {
        exe_name = exe_path;
    }
    
    // Build the message
    snprintf(message, message_size,
            "[ALERT] Rapid file modifications detected - Process %d (%s) modified %d files in %d seconds",
            pid, exe_name, tracker->recent_modifications, FREQUENCY_WINDOW_SECONDS);
    
    if (tracker->event_count > 0) {
        size_t offset = strlen(message);
        if (offset < message_size - 20) {
            strncpy(message + offset, " - Recent files: ", message_size - offset);
            offset += 16;
            
            // Add up to 3 most recent files
            for (int i = 0; i < 3 && i < tracker->event_count; i++) {
                int event_idx = (tracker->current_index - i - 1) % EVENTS_PER_PID;
                if (event_idx < 0) event_idx += EVENTS_PER_PID;
                
                // Get basename for brevity
                const char *path = tracker->events[event_idx].path;
                const char *basename = strrchr(path, '/');
                if (basename) {
                    basename++; 
                } else {
                    basename = path;
                }
                
                size_t remaining = message_size - offset;
                if (remaining > strlen(basename) + 5) {
                    if (i > 0) {
                        strncat(message + offset, ", ", remaining);
                        offset += 2;
                        remaining -= 2;
                    }
                    strncat(message + offset, basename, remaining);
                    offset += strlen(basename);
                } else {
                    break;
                }
            }
        }
    }
}

void reset_file_modification_tracker(pid_t pid) {
    for (int i = 0; i < pid_events_count; i++) {
        if (pid_file_events[i].pid == pid) {
            memset(&pid_file_events[i], 0, sizeof(pid_file_events_t));
            pid_file_events[i].pid = pid;
            pid_file_events[i].last_check_time = get_monotonic_time_ms();
            break;
        }
    }
}

#define EVENT_BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

static int fd;
static int wd;
static char *target_path;

bool init_file_monitor(const char *watch_path) {
    fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        perror("inotify_init");
        return false;
    }
    target_path = strdup(watch_path);    
    wd = inotify_add_watch(fd, target_path, 
                          IN_MODIFY | IN_CREATE | IN_DELETE |
                          IN_MOVED_FROM | IN_MOVED_TO);
    
    if (wd < 0) {
        perror("inotify_add_watch");
        close(fd);
        free(target_path);
        return false;
    }
    
    init_file_modification_tracker();
        
    return true;
}

void start_file_monitoring(void) {
    if (!keep_running) return;
    
    char buffer[EVENT_BUF_LEN];
    int length = read(fd, buffer, EVENT_BUF_LEN);
    if (length < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("read");
        }
        return;
    }
    
    int i = 0;
    while (i < length) {
        struct inotify_event *event = (struct inotify_event*)&buffer[i];
        if (event->len) {
            pid_t modifier_pid = get_file_modifier_pid(event->name);
            if (modifier_pid <= 0) {
                modifier_pid = getpid(); // Fallback
            }
            
            if (event->mask & IN_CREATE) {
                file_monitor_process_event(event->name, FILE_OP_CREATE, modifier_pid);
            } else if (event->mask & IN_DELETE) {
                file_monitor_process_event(event->name, FILE_OP_DELETE, modifier_pid);
            } else if (event->mask & IN_MODIFY) {
                file_monitor_process_event(event->name, FILE_OP_WRITE, modifier_pid);
            } else if (event->mask & IN_MOVED_FROM || event->mask & IN_MOVED_TO) {
                file_monitor_process_event(event->name, FILE_OP_RENAME, modifier_pid);
            }
        }
        i += sizeof(struct inotify_event) + event->len;
    }
}


void cleanup_file_monitor() {
    inotify_rm_watch(fd, wd);
    close(fd);
    free(target_path);
}

int check_and_update_threshold(void) {
    time_t now = time(NULL);
    
    if (now - last_threshold_check < 60) {
        return current_score_threshold;
    }
    
    last_threshold_check = now;
    
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        return current_score_threshold; 
    }
    
    double load_avg = (double)info.loads[0] / (1 << 16);
    
    int previous_threshold = current_score_threshold;
    
    if (load_avg > 5.0) {
        current_score_threshold = DEFAULT_SCORE_THRESHOLD * 2;
    } else if (load_avg > 2.0) {
        current_score_threshold = (int)(DEFAULT_SCORE_THRESHOLD * (1.0 + (load_avg - 2.0) * 0.25));
    } else {
        current_score_threshold = DEFAULT_SCORE_THRESHOLD;
    }
    
    if (!threshold_warning_logged && current_score_threshold > previous_threshold) {
        char message[256];
        snprintf(message, sizeof(message), 
                "[SYSTEM] Alert threshold increased from %d to %d due to high system load (%.2f)",
                previous_threshold, current_score_threshold, load_avg);
        log_suspicious_activity(message);
        threshold_warning_logged = true;
    } else if (threshold_warning_logged && current_score_threshold <= DEFAULT_SCORE_THRESHOLD) {
        threshold_warning_logged = false;
        char message[256];
        snprintf(message, sizeof(message), 
                "[SYSTEM] Alert threshold restored to %d - system load normal (%.2f)",
                current_score_threshold, load_avg);
        log_suspicious_activity(message);
    }
    
    return current_score_threshold;
}

void prepare_scoring_factors(scoring_factors_t *factors, const char *path, 
                            file_op_type_t op_type, pid_t pid, double entropy, bool high_frequency) {
    if (!factors) {
        return;
    }
    
    memset(factors, 0, sizeof(scoring_factors_t));
    
    factors->entropy = entropy / 8.0; // Normalize to 0.0-1.0 range
    
    factors->paths[0] = (char *)path;
    factors->path_count = 1;

    (void)op_type; // Unused for now
    
    const char *basename = strrchr(path, '/');
    if (basename && basename[1] == '.') {
        factors->hidden_file = true;
    }
    
    factors->high_frequency = high_frequency;
    
    pid_t ppid = get_parent_pid(pid);
    if (ppid > 0) {
        char parent_path[PATH_MAX] = {0};
        char proc_path[64] = {0};
        char exe_path[PATH_MAX] = {0};
        
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
        ssize_t len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = '\0';
        }
        
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", ppid);
        len = readlink(proc_path, parent_path, sizeof(parent_path) - 1);
        if (len > 0) {
            parent_path[len] = '\0';
            
            if ((strstr(parent_path, "python") && strstr(exe_path, "nc")) ||
                (strstr(parent_path, "bash") && strstr(exe_path, "wget")) ||
                (strstr(parent_path, "perl") && strstr(exe_path, "curl"))) {
                factors->suspicious_parent_child = true;
            }
        }
    }
    
    factors->network_correlation = has_recent_network_activity(pid);
    
    static pid_t recent_processes[10] = {0};
    static int recent_count = 0;
    static time_t last_reset = 0;
    
    time_t now = time(NULL);
    
    if (now - last_reset > 60) {
        memset(recent_processes, 0, sizeof(recent_processes));
        recent_count = 0;
        last_reset = now;
    }
    
    bool found = false;
    for (int i = 0; i < recent_count; i++) {
        if (recent_processes[i] == pid) {
            found = true;
            break;
        }
    }
    
    if (!found && recent_count < 10) {
        recent_processes[recent_count++] = pid;
    }
    
    factors->affected_processes = recent_count;
}

void file_monitor_process_event(const char *path, file_op_type_t op_type, pid_t pid) {
    if (path == NULL || pid <= 0) {
        return;
    }
    
    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", target_path, path);
    
    bool high_frequency = track_file_modification_frequency(pid, full_path, op_type);
    
    double entropy = -1.0;
    if (op_type == FILE_OP_WRITE || op_type == FILE_OP_CREATE) {
        entropy = analyze_file_entropy(full_path);
    }
    
    scoring_factors_t factors;
    prepare_scoring_factors(&factors, full_path, op_type, pid, entropy, high_frequency);
    
    int threshold = check_and_update_threshold();
    
    int score = calculate_score(pid, &factors);
    
    if (score >= threshold) {
        if (high_frequency) {
            char message[1024];
            get_frequency_report(pid, message, sizeof(message));
            log_suspicious_activity(message);
            
            char score_info[128];
            snprintf(score_info, sizeof(score_info), "[INFO] Event score: %d (threshold: %d)", 
                    score, threshold);
            log_suspicious_activity(score_info);
        }
        
        if (entropy > 0.7 && (op_type == FILE_OP_WRITE || op_type == FILE_OP_CREATE)) {
            char entropy_msg[512];
            snprintf(entropy_msg, sizeof(entropy_msg),
                    "[ENTROPY] File %s has high entropy (%.2f) - possible encryption",
                    path, entropy);
            log_suspicious_activity(entropy_msg);
        }
    } else {
        // If below threshold, only log at debug level if enabled
        // In a real implementation, you would use a debug logging function
        // Debug log would go here
    }
    
    // pass data to process_analyzer.c for tracking
    process_file_event(path, full_path, op_type, pid, entropy, high_frequency);
    
    if (factors.network_correlation && (op_type == FILE_OP_WRITE || op_type == FILE_OP_CREATE)) {
        track_network_and_file_activity(pid, TRACK_FILE, full_path, 0, 0, 0, entropy);
    }
}

pid_t get_file_modifier_pid(const char *filename) {
    DIR *proc_dir;
    struct dirent *pid_dir;
    char full_path[PATH_MAX];
    
    snprintf(full_path, PATH_MAX, "%s/%s", target_path, filename);
    
    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        return -1;
    }
    
    while ((pid_dir = readdir(proc_dir)) != NULL) {
        if (pid_dir->d_name[0] < '0' || pid_dir->d_name[0] > '9') {
            continue;
        }
        
        pid_t pid = atoi(pid_dir->d_name);
        
        if (process_has_file_open(pid, full_path)) {
            closedir(proc_dir);
            return pid;
        }
    }
    
    closedir(proc_dir);
    return -1; 
}

bool process_has_file_open(pid_t pid, const char *target_file) {
    DIR *fd_dir;
    struct dirent *fd_entry;
    char fd_path[PATH_MAX];
    char link_target[PATH_MAX];
    
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
    
    fd_dir = opendir(fd_path);
    if (fd_dir == NULL) {
        return false; 
    }
    
    while ((fd_entry = readdir(fd_dir)) != NULL) {
        if (fd_entry->d_name[0] == '.') {
            continue;
        }
        
        char link_path[PATH_MAX];
        ssize_t len;
        
        // Check if combined path would be too long
        if (strlen(fd_path) + strlen(fd_entry->d_name) + 2 > PATH_MAX) {
            continue;  // Skip if too long
        }
        
        // Safe alternative to snprintf
        strcpy(link_path, fd_path);
        strcat(link_path, "/");
        strcat(link_path, fd_entry->d_name);
        
        len = readlink(link_path, link_target, sizeof(link_target) - 1);
        if (len < 0) {
            continue;
        }
        
        link_target[len] = '\0';
        
        if (strcmp(link_target, target_file) == 0) {
            closedir(fd_dir);
            return true;
        }
    }
    
    closedir(fd_dir);
    return false;
}


bool has_recent_network_activity(pid_t pid) {
    char proc_net_path[PATH_MAX];
    char buffer[4096];
    FILE *net_file;
    bool has_network = false;
    
    snprintf(proc_net_path, sizeof(proc_net_path), "/proc/%d/net/tcp", pid);
    net_file = fopen(proc_net_path, "r");
    if (net_file) {
        if (fgets(buffer, sizeof(buffer), net_file) != NULL) {
            if (fgets(buffer, sizeof(buffer), net_file) != NULL) {
                has_network = true;
            }
        }
        fclose(net_file);
    }
    
    if (!has_network) {
        snprintf(proc_net_path, sizeof(proc_net_path), "/proc/%d/net/udp", pid);
        net_file = fopen(proc_net_path, "r");
        if (net_file) {
            if (fgets(buffer, sizeof(buffer), net_file) != NULL) {
                if (fgets(buffer, sizeof(buffer), net_file) != NULL) {
                    has_network = true;
                }
            }
            fclose(net_file);
        }
    }
    
    return has_network;
}

pid_t get_parent_pid(pid_t pid) {
    char stat_path[64];
    FILE *stat_file;
    char buffer[512];
    pid_t ppid = -1;
    
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    stat_file = fopen(stat_path, "r");
    if (!stat_file) {
        return -1;
    }
    
    if (fgets(buffer, sizeof(buffer), stat_file) != NULL) {
        char *start = strchr(buffer, ')');
        if (start) {
            start += 2;
            while (*start == ' ' || (*start != ' ' && *start != '\0')) {
                start++;
            }
            if (*start != '\0') {
                sscanf(start, "%d", &ppid);
            }
        }
    }
    
    fclose(stat_file);
    return ppid;
}

bool is_process_suspicious(pid_t pid) {
    char exec_path[PATH_MAX];
    char proc_path[64];
    
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(proc_path, exec_path, sizeof(exec_path) - 1);
    
    if (len <= 0) {
        return false; 
    }
    
    exec_path[len] = '\0';
    
    const char *suspicious_dirs[] = {
        "/tmp/", 
        "/dev/shm/",
        "/run/user/",
        "/var/tmp/",
        NULL
    };
    
    for (int i = 0; suspicious_dirs[i] != NULL; i++) {
        if (strncmp(exec_path, suspicious_dirs[i], strlen(suspicious_dirs[i])) == 0) {
            return true;
        }
    }
    
    pid_t ppid = get_parent_pid(pid);
    if (ppid > 0) {
        char parent_path[PATH_MAX];
        
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", ppid);
        len = readlink(proc_path, parent_path, sizeof(parent_path) - 1);
        
        if (len > 0) {
            parent_path[len] = '\0';
            
            if (strstr(parent_path, "python") && strstr(exec_path, "nc")) {
                return true; 
            }
            
        }
    }
    
    return false;
}