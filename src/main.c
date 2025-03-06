// main.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include "file_monitor.h"
#include "syscall_monitor.h"
#include "process_analyzer.h"
#include "syscall_filter.h"
#include "response.h"
#include "daemon_utils.h"

static volatile int keep_running = 1;
static const char *DEFAULT_PID_FILE = "/var/run/ransomguard.pid";
static const char *DEFAULT_CONFIG_FILE = "/etc/ransomguard.conf";
static const char *DEFAULT_WATCH_DIR = "/home";

void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        log_suspicious_activity("Received termination signal, shutting down...");
        keep_running = 0;
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

int main(int argc, char *argv[]) {
    // Default values
    char *pid_file = (char*)DEFAULT_PID_FILE;
    char *config_file = (char*)DEFAULT_CONFIG_FILE;
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

    // Run as daemon if requested
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

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize logging
    openlog("ransomguard", LOG_PID, LOG_DAEMON);
    log_suspicious_activity("RansomGuard daemon starting");

    // Initialize monitors
    int success = 1;
    if (!init_file_monitor(watch_dir)) {
        log_suspicious_activity("Failed to initialize file monitor");
        success = 0;
    }

    // If specific PID monitoring requested
    if (target_pid > 0) {
        if (!init_syscall_monitor(target_pid)) {
            log_suspicious_activity("Failed to initialize syscall monitor");
            success = 0;
        }
        
        if (!init_process_analyzer(target_pid)) {
            log_suspicious_activity("Failed to initialize process analyzer");
            success = 0;
        }
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
        // Monitor file activity
        // We'll need to modify file_monitoring to be non-blocking
        start_file_monitoring_cycle();  // Assume this is a non-blocking version
        
        // Monitor process if specified
        if (target_pid > 0) {
            analyze_process();
            monitor_syscalls_cycle();   // Assume this is a non-blocking version
        }
        
        // Sleep to reduce CPU usage
        sleep(1);
    }

    // Cleanup
    log_suspicious_activity("Shutting down");
    cleanup_file_monitor();
    
    if (target_pid > 0) {
        cleanup_process_analyzer();
        cleanup_syscall_monitor();
    }

    if (run_as_daemon) {
        remove_pid_file(pid_file);
    }
    
    closelog();
    return EXIT_SUCCESS;
}