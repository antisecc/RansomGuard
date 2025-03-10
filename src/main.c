// main.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <syslog.h>
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

volatile int keep_running = 1;
static volatile int force_exit = 0;
static const char *DEFAULT_PID_FILE = "/var/run/ransomguard.pid";
static const char *DEFAULT_CONFIG_FILE = "/etc/ransomguard.conf";
static const char *DEFAULT_WATCH_DIR = "/home";

static int file_ops_threshold = 50;
static double entropy_threshold = 0.8;
static int max_tracked_files = 5000;
static int max_concurrent_file_ops = 20;
static bool kill_suspicious_processes = false;

void force_exit_handler(int sig){
    (void)sig;
    log_suspicious_activity("Forced exit signal received, shutting down...");
    force_exit = 1;
    exit(EXIT_FAILURE);
}

void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        log_suspicious_activity("Received termination signal, shutting down...");
        keep_running = 0;

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
    fprintf(stderr, "  -h, --help                Display this help and exit\n");
}

bool init_all(const char *watch_dir, pid_t target_pid) {
    (void)target_pid;  // Mark as intentionally unused
    if (!init_file_monitor(watch_dir)) {
        log_suspicious_activity("Failed to initialize file monitor");
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

void handle_threat(const char *message, pid_t suspicious_pid) {
    log_suspicious_activity(message);
    
    if (kill_suspicious_processes && suspicious_pid > 0) {
        char action_msg[256];
        snprintf(action_msg, sizeof(action_msg), "Terminating suspicious process %d", suspicious_pid);
        log_suspicious_activity(action_msg);
        
        if (kill(suspicious_pid, SIGTERM) == 0) {
            log_suspicious_activity("Process terminated successfully");
        } else {
            log_suspicious_activity("Failed to terminate process");
        }
    }
}

int main(int argc, char *argv[]) {
    // Default values
    char *pid_file = (char*)DEFAULT_PID_FILE;
    char *config_file = (char*)DEFAULT_CONFIG_FILE;
    (void)config_file;
    char *watch_dir = (char*)DEFAULT_WATCH_DIR;
    pid_t target_pid = -1;
    int run_as_daemon = 0;

    // Parse command line options
    static struct option long_options[] = {
        {"daemon",      no_argument,       0, 'd'},
        {"pidfile",     required_argument, 0, 'p'},
        {"config",      required_argument, 0, 'c'},
        {"watchdir",    required_argument, 0, 'w'},
        {"monitor-pid", required_argument, 0, 'm'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "dp:c:w:m:h", long_options, &option_index)) != -1) {
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
    
    openlog("ransomguard", LOG_PID, LOG_DAEMON);
    log_suspicious_activity("RansomGuard daemon starting");

    int success = 1;
    if (!init_all(watch_dir, target_pid)) {
        log_suspicious_activity("Initialization failed, shutting down");
        success = 0;
    }

    if (!success) {
        log_suspicious_activity("Initialization failed, shutting down");
        if (run_as_daemon) {
            remove_pid_file(pid_file);
        }
        return EXIT_FAILURE;
    }

    log_suspicious_activity("Monitoring started");
    
    // Main monitoring loop
    while (keep_running) {
        start_file_monitoring();
        
        suspicious_activity_t activity;
        if (detect_suspicious_activity(&activity)) {
            char message[1024];
            snprintf(message, sizeof(message), 
                    "[ALERT] Suspicious file activity detected on %s (operations: %d, entropy: %.2f)",
                    activity.path, activity.operation_count, activity.entropy);
            handle_threat(message, -1);
        }
        
        // Monitor proc 
        if (target_pid > 0) {
            process_info_t proc_results[10];
            int proc_count = analyze_process_relationships(target_pid, proc_results, 10);
            
            for (int i = 0; i < proc_count; i++) {
                char message[1024];
                snprintf(message, sizeof(message),
                        "[ALERT] Suspicious process detected: PID=%d, Path=%s",
                        proc_results[i].pid, proc_results[i].exec_path);
                handle_threat(message, proc_results[i].pid);
            }
            
            // patterns
            syscall_pattern_result_t pattern_results[5];
            int pattern_count = analyze_syscall_patterns(target_pid, pattern_results, 5);
            
            for (int i = 0; i < pattern_count; i++) {
                char message[1024];
                snprintf(message, sizeof(message),
                        "[ALERT] Suspicious syscall pattern detected: PID=%d, Type=%d, Confidence=%d%%, Description=%s",
                        pattern_results[i].pid, pattern_results[i].pattern_type,
                        pattern_results[i].confidence, pattern_results[i].description);
                handle_threat(message, pattern_results[i].pid);
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
    cleanup_behavioral_analysis();
    cleanup_process_relationship();
    cleanup_syscall_pattern();
    cleanup_hash_monitor();
}