// main.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/resource.h>
#include "file_monitor.h"
#include "syscall_monitor.h"
#include "process_analyzer.h"
#include "syscall_filter.h"
#include "response.h"
#include "daemon_utils.h"
#include "behavioral_analysis.h"
#include "entropy_analysis.h"
#include "process_relationship.h"
#include "syscall_pattern.h"
#include "hash_monitor.h"
#include "whitelist.h"
#include "activity_scorer.h"
#include "logger.h"

volatile int keep_running = 1;
static volatile int force_exit = 0;
static const char *DEFAULT_PID_FILE = "/var/run/ransomguard.pid";
static const char *DEFAULT_CONFIG_FILE = "/etc/ransomguard.conf";
static const char *DEFAULT_WATCH_DIR = "/home";

static int file_ops_threshold = 50;
static double entropy_threshold = 0.8;
static int max_tracked_files = 5000;
static bool kill_suspicious_processes = false;
static int entropy_monitoring_window = 30;
static int high_entropy_threshold = 5;
static int detection_sensitivity = 2; // 1=low, 2=medium, 3=high
static int verbosity_level = 1;       // 0=quiet, 1=normal, 2=verbose, 3=debug

// function declarations
void signal_handler(int sig);
void force_exit_handler(int sig);
void print_usage(const char *program_name);
bool init_all(const char *watch_dir, const char *config_file, pid_t target_pid);
void handle_threat(const char *message, pid_t suspicious_pid, int severity);
void cleanup_all(void);
void set_process_priority(void);
void parse_config_file(const char *config_file);

void force_exit_handler(int sig) {
    (void)sig;
    log_suspicious_activity("Forced exit signal received, shutting down...");
    force_exit = 1;
    exit(EXIT_FAILURE);
}

void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        log_suspicious_activity("Received termination signal, shutting down...");
        keep_running = 0;

        // exit handler if hang during cleanup
        signal(SIGTERM, force_exit_handler);
        alarm(5);
    }
}

void print_usage(const char *program_name) {
    fprintf(stderr, "RansomGuard - Ransomware Detection and Prevention Daemon\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [OPTIONS]\n\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d, --daemon              Run as daemon\n");
    fprintf(stderr, "  -p, --pidfile=FILE        PID file path (default: %s)\n", DEFAULT_PID_FILE);
    fprintf(stderr, "  -c, --config=FILE         Config file path (default: %s)\n", DEFAULT_CONFIG_FILE);
    fprintf(stderr, "  -w, --watchdir=DIR        Directory to monitor (default: %s)\n", DEFAULT_WATCH_DIR);
    fprintf(stderr, "  -m, --monitor-pid=PID     Specific process PID to monitor\n");
    fprintf(stderr, "  -k, --kill-suspicious     Terminate suspicious processes\n");
    fprintf(stderr, "  -s, --sensitivity=LEVEL   Detection sensitivity (1=low, 2=medium, 3=high)\n");
    fprintf(stderr, "  -v, --verbose=LEVEL       Verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug)\n");
    fprintf(stderr, "  -h, --help                Display this help and exit\n");
}

void set_process_priority(void) {
    setpriority(PRIO_PROCESS, 0, -10);    
    // Lock memory to prevent swapping
    struct rlimit limit;
    if (getrlimit(RLIMIT_MEMLOCK, &limit) == 0) {
        limit.rlim_cur = limit.rlim_max;
        setrlimit(RLIMIT_MEMLOCK, &limit);
    }
}

void parse_config_file(const char *config_file) {
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        log_suspicious_activity("Warning: Could not open config file, using default settings");
        return;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        char key[128], value[128];
        if (sscanf(line, "%127[^=]=%127s", key, value) == 2) {
            char *p = key + strlen(key) - 1;
            while (p >= key && isspace(*p)) {
                *p-- = '\0';
            }
            
            // Process configuration settings
            if (strcmp(key, "file_ops_threshold") == 0) {
                file_ops_threshold = atoi(value);
            } else if (strcmp(key, "entropy_threshold") == 0) {
                entropy_threshold = atof(value);
            } else if (strcmp(key, "max_tracked_files") == 0) {
                max_tracked_files = atoi(value);
            } else if (strcmp(key, "kill_suspicious_processes") == 0) {
                kill_suspicious_processes = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
            } else if (strcmp(key, "entropy_monitoring_window") == 0) {
                entropy_monitoring_window = atoi(value);
            } else if (strcmp(key, "high_entropy_threshold") == 0) {
                high_entropy_threshold = atoi(value);
            } else if (strcmp(key, "detection_sensitivity") == 0) {
                detection_sensitivity = atoi(value);
                if (detection_sensitivity < 1) detection_sensitivity = 1;
                if (detection_sensitivity > 3) detection_sensitivity = 3;
            } else if (strcmp(key, "verbosity_level") == 0) {
                verbosity_level = atoi(value);
                if (verbosity_level < 0) verbosity_level = 0;
                if (verbosity_level > 3) verbosity_level = 3;
            }
        }
    }
    
    fclose(fp);
    
    if (verbosity_level >= 2) {
        log_suspicious_activity("Configuration loaded from file");
    }
}

bool init_all(const char *watch_dir, const char *config_file, pid_t target_pid) {
    if (!init_logger(verbosity_level)) {
        fprintf(stderr, "Failed to initialize logger\n");
        return false;
    }
    
    if (config_file) {
        parse_config_file(config_file);
    }
    
    if (!init_file_monitor(watch_dir)) {
        log_suspicious_activity("Failed to initialize file monitor");
        return false;
    }
    
    if (!init_entropy_analysis()) {
        log_suspicious_activity("Failed to initialize entropy analysis");
        return false;
    }
    
    if (target_pid > 0) {
        if (!init_process_analyzer(target_pid)) {
            log_suspicious_activity("Failed to initialize process analyzer");
            return false;
        }
    }
    
    if (!init_syscall_filter()) {
        log_suspicious_activity("Failed to initialize syscall filter");
        return false;
    }
    
    if (!init_whitelist(config_file)) {
        log_suspicious_activity("Failed to initialize process whitelist");
        return false;
    }
    
    if (!init_activity_scorer()) {
        log_suspicious_activity("Failed to initialize activity scorer");
        return false;
    }
    
    if (!init_behavioral_analysis(max_tracked_files, file_ops_threshold, entropy_threshold)) {
        log_suspicious_activity("Failed to initialize behavioral analysis");
        return false;
    }
    
    if (!init_process_relationship()) {
        log_suspicious_activity("Failed to initialize process relationship analysis");
        return false;
    }
    
    if (!init_syscall_pattern()) {
        log_suspicious_activity("Failed to initialize syscall pattern analysis");
        return false;
    }
    
    if (!init_hash_monitor(max_tracked_files)) {
        log_suspicious_activity("Failed to initialize hash monitor");
        return false;
    }
    
    return true;
}

void handle_threat(const char *message, pid_t suspicious_pid, int severity) {
    log_suspicious_activity(message);
    
    if (severity >= 3) { 
        if (kill_suspicious_processes && suspicious_pid > 0) {
            char action_msg[256];
            snprintf(action_msg, sizeof(action_msg), 
                    "Terminating suspicious process %d due to critical threat", suspicious_pid);
            log_suspicious_activity(action_msg);
            
            if (kill(suspicious_pid, SIGTERM) == 0) {
                log_suspicious_activity("Process terminated successfully");
                
                usleep(100000); // 100ms
                
                // SIGKILL
                if (kill(suspicious_pid, 0) == 0) {
                    log_suspicious_activity("Process still running, sending SIGKILL");
                    kill(suspicious_pid, SIGKILL);
                }
            } else {
                log_suspicious_activity("Failed to terminate process");
            }
        }
        
        // TODO: We could add additional responses here like:
        // - Snapshot the file system
        // - Send alerts via email/SMS
        // - Block network access
    }
    else if (severity >= 2) { 
        if (suspicious_pid > 0) {
            filter_syscall(suspicious_pid, kill_suspicious_processes);
            
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "ps -p %d -o pid,ppid,cmd > /var/log/ransomguard/process_%d.log", 
                    suspicious_pid, suspicious_pid);
            system(cmd);
        }
    }
}

int main(int argc, char *argv[]) {
    char *pid_file = (char*)DEFAULT_PID_FILE;
    char *config_file = (char*)DEFAULT_CONFIG_FILE;
    char *watch_dir = (char*)DEFAULT_WATCH_DIR;
    pid_t target_pid = -1;
    int run_as_daemon = 0;

    static struct option long_options[] = {
        {"daemon",       no_argument,       0, 'd'},
        {"pidfile",      required_argument, 0, 'p'},
        {"config",       required_argument, 0, 'c'},
        {"watchdir",     required_argument, 0, 'w'},
        {"monitor-pid",  required_argument, 0, 'm'},
        {"kill-suspicious", no_argument,    0, 'k'},
        {"sensitivity",  required_argument, 0, 's'},
        {"verbose",      required_argument, 0, 'v'},
        {"help",         no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "dp:c:w:m:ks:v:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'd':
                run_as_daemon = 1;
                break;
            case 'p':
                pid_file = optarg;
                break;
            case 'c':
                config_file = optarg;
                break;
            case 'w':
                watch_dir = optarg;
                break;
            case 'm':
                target_pid = atoi(optarg);
                break;
            case 'k':
                kill_suspicious_processes = true;
                break;
            case 's':
                detection_sensitivity = atoi(optarg);
                if (detection_sensitivity < 1) detection_sensitivity = 1;
                if (detection_sensitivity > 3) detection_sensitivity = 3;
                break;
            case 'v':
                verbosity_level = atoi(optarg);
                if (verbosity_level < 0) verbosity_level = 0;
                if (verbosity_level > 3) verbosity_level = 3;
                break;
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    // daemon if requested
    if (run_as_daemon) {
        if (!daemonize()) {
            fprintf(stderr, "Failed to daemonize\n");
            return EXIT_FAILURE;
        }

        if (!write_pid_file(pid_file)) {
            fprintf(stderr, "Failed to create PID file\n");
            return EXIT_FAILURE;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Set up process priority
    set_process_priority();
    
    // Open syslog
    openlog("ransomguard", LOG_PID, LOG_DAEMON);
    log_suspicious_activity("RansomGuard daemon starting");

    // Initialize all components
    if (!init_all(watch_dir, config_file, target_pid)) {
        log_suspicious_activity("Initialization failed, shutting down");
        if (run_as_daemon) {
            remove_pid_file(pid_file);
        }
        closelog();
        return EXIT_FAILURE;
    }

    log_suspicious_activity("Monitoring started");
    
    // Display configuration summary
    char config_summary[512];
    snprintf(config_summary, sizeof(config_summary), 
            "Configuration: sensitivity=%d, verbosity=%d, kill_suspicious=%s, max_files=%d", 
            detection_sensitivity, verbosity_level, 
            kill_suspicious_processes ? "yes" : "no", max_tracked_files);
    log_suspicious_activity(config_summary);
    
    // Main monitoring loop
    while (keep_running) {
        update_alert_threshold();
        
        start_file_monitoring();
        
        suspicious_activity_t activity;
        if (detect_suspicious_activity(&activity)) {
            char message[1024];
            snprintf(message, sizeof(message), 
                    "[ALERT] Suspicious file activity detected on %s (operations: %d, entropy: %.2f)",
                    activity.path, activity.operation_count, activity.entropy);
            
            int severity = 1; // 
            if (activity.entropy > 0.9 && activity.operation_count > file_ops_threshold) {
                severity = 3; // 
            } else if (activity.entropy > 0.7 || activity.operation_count > file_ops_threshold / 2) {
                severity = 2; // 
            }
            
            handle_threat(message, activity.pid, severity);
        }
        
        network_file_stats_t net_stats;
        get_network_file_stats(&net_stats);
        
        if (net_stats.suspicious_processes > 0 && verbosity_level >= 2) {
            char net_message[512];
            snprintf(net_message, sizeof(net_message),
                    "[WARNING] Detected %d process(es) with suspicious network and file activity",
                    net_stats.suspicious_processes);
            log_suspicious_activity(net_message);
        }
        
        if (target_pid > 0) {
            process_info_t proc_results[10];
            int proc_count = analyze_process_relationships(target_pid, proc_results, 10);
            
            for (int i = 0; i < proc_count; i++) {
                char message[1024];
                snprintf(message, sizeof(message),
                        "[ALERT] Suspicious process detected: PID=%d, Path=%s",
                        proc_results[i].pid, proc_results[i].exec_path);
                handle_threat(message, proc_results[i].pid, 2);
            }
            
            syscall_pattern_result_t pattern_results[5];
            int pattern_count = analyze_syscall_patterns(target_pid, pattern_results, 5);
            
            for (int i = 0; i < pattern_count; i++) {
                char message[1024];
                snprintf(message, sizeof(message),
                        "[ALERT] Suspicious syscall pattern detected: PID=%d, Type=%d, Confidence=%d%%, Description=%s",
                        pattern_results[i].pid, pattern_results[i].pattern_type,
                        pattern_results[i].confidence, pattern_results[i].description);
                
                int severity = 1;
                if (pattern_results[i].confidence >= 90) {
                    severity = 3;
                } else if (pattern_results[i].confidence >= 70) {
                    severity = 2;
                }
                
                handle_threat(message, pattern_results[i].pid, severity);
            }
            
            if (detection_sensitivity >= 2) {
                filter_syscall(target_pid, kill_suspicious_processes && detection_sensitivity >= 3);
            }
        }

        if (!keep_running) {
            break;
        }

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;  // 100ms
        select(0, NULL, NULL, NULL, &tv);
    }

    log_suspicious_activity("Shutting down");
    cleanup_all();
    
    if (run_as_daemon) {
        remove_pid_file(pid_file);
    }
    
    closelog();
    return EXIT_SUCCESS;
}

void cleanup_all(void) {
    cleanup_file_monitor();
    cleanup_process_analyzer();
    cleanup_syscall_filter();
    cleanup_behavioral_analysis();
    cleanup_entropy_analysis();
    cleanup_process_relationship();
    cleanup_syscall_pattern();
    cleanup_hash_monitor();
    cleanup_whitelist();
    cleanup_activity_scorer();
    cleanup_logger();
}