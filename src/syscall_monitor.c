// syscall_monitor.c
#include "syscall_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <linux/ptrace.h>

static pid_t monitored_pid = -1;

// Suspicious syscall counter for different types
static struct {
    int file_writes;
    int file_deletes;
    int file_renames;
    int chmod_calls;
} suspicious_activity = {0};

// Constants for detection thresholds
#define THRESHOLD_WRITES  50  // High number of writes in short period
#define THRESHOLD_DELETES 10  // Multiple deletes in short period
#define THRESHOLD_RENAMES 20  // Multiple renames in short period

bool init_syscall_monitor(pid_t target_pid) {
    monitored_pid = target_pid;
    
    // Attach to the process
    if (ptrace(PTRACE_ATTACH, monitored_pid, NULL, NULL) < 0) {
        perror("ptrace attach");
        return false;
    }
    
    // Wait for the process to stop
    int status;
    waitpid(monitored_pid, &status, 0);
    
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Failed to stop the target process\n");
        return false;
    }
    
    // Set options to trace all syscalls
    if (ptrace(PTRACE_SETOPTIONS, monitored_pid, 0, 
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK) < 0) {
        perror("ptrace setoptions");
        ptrace(PTRACE_DETACH, monitored_pid, NULL, NULL);
        return false;
    }
    
    return true;
}

static void handle_syscall(pid_t pid, struct user_regs_struct *regs) {
    // Get syscall number
    long syscall_num = regs->orig_rax;
    
    // Check for suspicious syscalls
    switch (syscall_num) {
        case SYS_write:
            suspicious_activity.file_writes++;
            if (suspicious_activity.file_writes > THRESHOLD_WRITES) {
                printf("[ALERT] Process %d: High frequency of write operations detected\n", pid);
                // Reset counter after alert
                suspicious_activity.file_writes = 0;
            }
            break;
            
        case SYS_unlink:
            suspicious_activity.file_deletes++;
            if (suspicious_activity.file_deletes > THRESHOLD_DELETES) {
                printf("[ALERT] Process %d: Multiple file deletions detected\n", pid);
                suspicious_activity.file_deletes = 0;
            }
            break;
            
        case SYS_rename:
            suspicious_activity.file_renames++;
            if (suspicious_activity.file_renames > THRESHOLD_RENAMES) {
                printf("[ALERT] Process %d: Multiple file renames detected\n", pid);
                suspicious_activity.file_renames = 0;
            }
            break;
            
        case SYS_chmod:
            suspicious_activity.chmod_calls++;
            if (suspicious_activity.chmod_calls > 10) { // Threshold for chmod
                printf("[ALERT] Process %d: Multiple permission changes detected\n", pid);
                suspicious_activity.chmod_calls = 0;
            }
            break;
    }
}

void start_syscall_monitoring() {
    int status;
    struct user_regs_struct regs;
    
    printf("Monitoring syscalls for PID: %d\n", monitored_pid);
    
    // Tell the process to continue and stop at the next syscall
    if (ptrace(PTRACE_SYSCALL, monitored_pid, NULL, NULL) < 0) {
        perror("ptrace syscall");
        return;
    }
    
    while (1) {
        // Wait for the process to stop
        waitpid(monitored_pid, &status, 0);
        
        if (WIFEXITED(status)) {
            printf("Process %d exited\n", monitored_pid);
            break;
        }
        
        // Get the registers containing syscall information
        if (ptrace(PTRACE_GETREGS, monitored_pid, NULL, &regs) < 0) {
            perror("ptrace getregs");
            break;
        }
        
        // Process the syscall
        handle_syscall(monitored_pid, &regs);
        
        // Continue to the next syscall
        if (ptrace(PTRACE_SYSCALL, monitored_pid, NULL, NULL) < 0) {
            perror("ptrace syscall");
            break;
        }
    }
}

void cleanup_syscall_monitor() {
    if (monitored_pid != -1) {
        ptrace(PTRACE_DETACH, monitored_pid, NULL, NULL);
        monitored_pid = -1;
    }
}