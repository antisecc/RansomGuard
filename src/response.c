// response.c
#include "response.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <time.h>

void log_suspicious_activity(const char *message) {
    // Log to syslog
    openlog("ransomware-detector", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_WARNING, "%s", message);
    closelog();
    
    // Log to stdout with timestamp
    time_t now = time(NULL);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    printf("[%s] %s\n", timestr, message);
}

bool terminate_process(pid_t pid) {
    char message[256];
    snprintf(message, sizeof(message), "Terminating suspicious process with PID: %d", pid);
    log_suspicious_activity(message);
    
    if (kill(pid, SIGTERM) == 0) {
        // Give the process a chance to terminate gracefully
        usleep(500000);  // 500ms wait
        
        // Check if still running and force kill if necessary
        if (kill(pid, 0) == 0) {
            if (kill(pid, SIGKILL) == 0) {
                log_suspicious_activity("Process forcefully terminated with SIGKILL");
                return true;
            } else {
                perror("kill (SIGKILL)");
                return false;
            }
        }
        return true;
    } else {
        perror("kill (SIGTERM)");
        return false;
    }
}

bool protect_file(const char *filepath) {
    // Make file immutable or read-only
    if (chmod(filepath, S_IRUSR | S_IRGRP | S_IROTH) == 0) {
        char message[512];
        snprintf(message, sizeof(message), "Protected file: %s by making it read-only", filepath);
        log_suspicious_activity(message);
        return true;
    } else {
        perror("chmod");
        return false;
    }
}