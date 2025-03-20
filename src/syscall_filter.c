// syscall_filter.c
#include "syscall_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include "activity_scorer.h"
#include "logger.h"

// Define SCMP_ACT_TRACE if not available in the system headers
// This needs to be defined as a constant matching what libseccomp expects
#ifndef SCMP_ACT_TRACE
#define SCMP_ACT_TRACE SCMP_ACT_TRAP  // Use TRAP as fallback if TRACE not available
#endif

#define SUSPICIOUS_MEMORY_WINDOW 30  // 30 seconds 
#define MAX_TRACKED_PROCESSES 128    

typedef struct {
    pid_t pid;                  
    time_t first_event_time;    
    int event_count;            
    bool has_mprotect_rwx;       
    bool has_mmap_anon_exec;    
    bool reported;               
} memory_protection_tracker_t;

typedef struct {
    pid_t pid;                
    bool block_suspicious;    
} filter_thread_args_t;

static memory_protection_tracker_t mem_trackers[MAX_TRACKED_PROCESSES];
static int tracker_count = 0;
static pthread_mutex_t tracker_mutex = PTHREAD_MUTEX_INITIALIZER;

void init_memory_protection_tracking(void) {
    pthread_mutex_lock(&tracker_mutex);
    memset(mem_trackers, 0, sizeof(mem_trackers));
    tracker_count = 0;
    pthread_mutex_unlock(&tracker_mutex);
}

memory_protection_tracker_t* find_memory_tracker(pid_t pid) {
    pthread_mutex_lock(&tracker_mutex);
    
    for (int i = 0; i < tracker_count; i++) {
        if (mem_trackers[i].pid == pid) {
            pthread_mutex_unlock(&tracker_mutex);
            return &mem_trackers[i];
        }
    }
    
    if (tracker_count < MAX_TRACKED_PROCESSES) {
        memory_protection_tracker_t* tracker = &mem_trackers[tracker_count++];
        memset(tracker, 0, sizeof(memory_protection_tracker_t));
        tracker->pid = pid;
        tracker->first_event_time = time(NULL);
        pthread_mutex_unlock(&tracker_mutex);
        return tracker;
    }
    
    int oldest_idx = 0;
    time_t oldest_time = mem_trackers[0].first_event_time;
    
    for (int i = 1; i < MAX_TRACKED_PROCESSES; i++) {
        if (mem_trackers[i].first_event_time < oldest_time) {
            oldest_time = mem_trackers[i].first_event_time;
            oldest_idx = i;
        }
    }
    
    memory_protection_tracker_t* tracker = &mem_trackers[oldest_idx];
    memset(tracker, 0, sizeof(memory_protection_tracker_t));
    tracker->pid = pid;
    tracker->first_event_time = time(NULL);
    
    pthread_mutex_unlock(&tracker_mutex);
    return tracker;
}

bool track_memory_protection_event(pid_t pid, long syscall_num, unsigned long args[6]) {
    memory_protection_tracker_t* tracker = find_memory_tracker(pid);
    if (!tracker) {
        return false;
    }
    
    time_t now = time(NULL);
    bool is_suspicious = false;
    char reason[256] = {0};
    
    if (now - tracker->first_event_time > SUSPICIOUS_MEMORY_WINDOW) {
        tracker->first_event_time = now;
        tracker->has_mprotect_rwx = false;
        tracker->has_mmap_anon_exec = false;
        tracker->event_count = 0;
        tracker->reported = false;
    }
    
    if (syscall_num == SYS_mprotect) {
        unsigned long prot = args[2];
        
        if ((prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) == 
            (PROT_READ | PROT_WRITE | PROT_EXEC)) {
            
            tracker->has_mprotect_rwx = true;
            tracker->event_count++;
            
            snprintf(reason, sizeof(reason), 
                    "Process %d used mprotect to set RWX permissions at 0x%lx (size: %lu)",
                    pid, args[0], args[1]);
            is_suspicious = true;
        }
    }
    else if (syscall_num == SYS_mmap) {
        unsigned long prot = args[2];
        unsigned long flags = args[3];
        
        if ((flags & MAP_ANONYMOUS) && (prot & PROT_EXEC)) {
            tracker->has_mmap_anon_exec = true;
            tracker->event_count++;
            
            snprintf(reason, sizeof(reason), 
                    "Process %d created anonymous executable memory mapping of size %lu",
                    pid, args[1]);
            is_suspicious = true;
        }
    }
    
    if (tracker->has_mprotect_rwx && tracker->has_mmap_anon_exec && !tracker->reported) {
        tracker->reported = true;
        
        char process_name[256] = "unknown";
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/comm", pid);
        
        FILE* comm_file = fopen(proc_path, "r");
        if (comm_file) {
            if (fgets(process_name, sizeof(process_name), comm_file)) {
                size_t len = strlen(process_name);
                if (len > 0 && process_name[len-1] == '\n') {
                    process_name[len-1] = '\0';
                }
            }
            fclose(comm_file);
        }
        
        char message[512];
        snprintf(message, sizeof(message), 
                "[CRITICAL] Code injection detected in process %d (%s): Both mprotect(RWX) and mmap(ANON+EXEC) used",
                pid, process_name);
        log_suspicious_activity(message);
        
        score_syscall_event(pid, SCORE_MEMORY_INJECTION, NULL, 0.0);
        
        return true;
    }
    
    if (is_suspicious && reason[0] != '\0') {
        if (tracker->event_count <= 3 || tracker->event_count % 10 == 0) {
            char message[512];
            snprintf(message, sizeof(message), "[WARNING] Suspicious memory operation: %s", reason);
            log_suspicious_activity(message);
        }
        
        score_syscall_event(pid, 
                            syscall_num == SYS_mprotect ? SCORE_MEMORY_PROTECTION : SCORE_MEMORY_MAPPING, 
                            NULL, 0.0);
    }
    
    return is_suspicious;
}

bool attach_syscall_monitor(pid_t pid) {
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    
    if (access(proc_path, F_OK) != 0) {
        return false;
    }
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace(ATTACH)");
        return false;
    }
    
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, 
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | 
               PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE) < 0) {
        perror("ptrace(SETOPTIONS)");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
    return true;
}

void detach_syscall_monitor(pid_t pid) {
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

int filter_syscalls(pid_t pid, bool block_suspicious) {
    if (!attach_syscall_monitor(pid)) {
        return -1;
    }
    
    int status;
    int suspicious_count = 0;
    bool in_syscall = false;
    long syscall_num = -1;
    unsigned long args[6]; 
    
    while (1) {
        if (ptrace(in_syscall ? PTRACE_SYSCALL : PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
            perror("ptrace(SYSCALL)");
            break;
        }
        
        if (waitpid(pid, &status, 0) < 0) {
            if (errno == ECHILD) {
                break;
            }
            perror("waitpid");
            break;
        }
        
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }
        
        if (!WIFSTOPPED(status) || (status >> 8) != (SIGTRAP | 0x80)) {
            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);
                if (sig != SIGTRAP) {
                    ptrace(PTRACE_SYSCALL, pid, NULL, (void*)(intptr_t)sig);
                    continue;
                }
            }
            continue;
        }
        
        in_syscall = !in_syscall;
        
        if (in_syscall) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
                perror("ptrace(GETREGS)");
                break;
            }
            
            #ifdef __x86_64__
            syscall_num = regs.orig_rax;
            args[0] = regs.rdi;
            args[1] = regs.rsi;
            args[2] = regs.rdx;
            args[3] = regs.r10;
            args[4] = regs.r8;
            args[5] = regs.r9;
            #else
            syscall_num = regs.orig_eax;
            args[0] = regs.ebx;
            args[1] = regs.ecx;
            args[2] = regs.edx;
            args[3] = regs.esi;
            args[4] = regs.edi;
            args[5] = regs.ebp;
            #endif
            
            if (syscall_num == SYS_mmap || syscall_num == SYS_mprotect) {
                bool is_suspicious = track_memory_protection_event(pid, syscall_num, args);
                
                if (is_suspicious && block_suspicious) {
                    #ifdef __x86_64__
                    regs.orig_rax = -1;
                    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
                        perror("ptrace(SETREGS)");
                    }
                    #else
                    regs.orig_eax = -1;
                    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
                        perror("ptrace(SETREGS)");
                    }
                    #endif
                    
                    suspicious_count++;
                }
            }
        }
        
        if (status >> 16) {
            unsigned long event = status >> 16;
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
                pid_t child_pid;
                if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child_pid) < 0) {
                    perror("ptrace(GETEVENTMSG)");
                    continue;
                }
                
                waitpid(child_pid, &status, 0);
                
                ptrace(PTRACE_SETOPTIONS, child_pid, NULL, 
                      PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | 
                      PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
            }
        }
    }
    
    if (kill(pid, 0) == 0) {
        detach_syscall_monitor(pid);
    }
    
    return suspicious_count;
}

void *syscall_filter_thread(void *arg) {
    filter_thread_args_t *args = (filter_thread_args_t *)arg;
    pid_t pid = args->pid;
    bool block_suspicious = args->block_suspicious;
    
    free(args);
    
    filter_syscalls(pid, block_suspicious);
    return NULL;
}

// Fix setup_seccomp_filter function
bool setup_seccomp_filter(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        perror("seccomp_init");
        return false;
    }
    
    // Use SCMP_ACT_TRAP as a more universally available alternative
    // or define action as a variable for clarity
    uint32_t trace_action = SCMP_ACT_TRAP;  // Use TRAP instead of the custom TRACE
    
    if (seccomp_rule_add(ctx, trace_action, SCMP_SYS(mprotect), 0) < 0 ||
        seccomp_rule_add(ctx, trace_action, SCMP_SYS(mmap), 0) < 0) {
        perror("seccomp_rule_add");
        seccomp_release(ctx);
        return false;
    }
    
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        return false;
    }
    
    seccomp_release(ctx);
    return true;
}

// Update function body to match the new signature
bool filter_syscall(pid_t pid, bool block_suspicious) {
    static bool initialized = false;
    if (!initialized) {
        init_memory_protection_tracking();
        initialized = true;
    }
    
    if (pid == 0) {
        return setup_seccomp_filter();  // Updated to match new signature
    }
    
    pthread_t monitor_thread;
    filter_thread_args_t *args = malloc(sizeof(filter_thread_args_t));
    if (!args) {
        return false;
    }
    
    args->pid = pid;
    args->block_suspicious = block_suspicious;
    
    if (pthread_create(&monitor_thread, NULL, syscall_filter_thread, args) != 0) {
        free(args);
        return false;
    }
    
    pthread_detach(monitor_thread);
    return true;
}

// Add cleanup_syscall_filter function implementation if it doesn't exist
void cleanup_syscall_filter(void) {
    // Clean up any resources used by the syscall filter
    // Currently nothing to clean up (resources are freed in individual functions)
    return;
}

bool init_syscall_filter() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize seccomp filter\n");
        return false;
    }
    
    printf("Initialized seccomp filter\n");
    seccomp_release(ctx);
    return true;
}

bool apply_restrictive_policy() {
    // Create seccomp context with default allow
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize seccomp filter\n");
        return false;
    }
    
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(unlink), 0) != 0) {
        fprintf(stderr, "Failed to add unlink rule\n");
        seccomp_release(ctx);
        return false;
    }
    
    // Block unlinkat syscall 
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(unlinkat), 0) != 0) {
        fprintf(stderr, "Failed to add unlinkat rule\n");
        seccomp_release(ctx);
        return false;
    }
    
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(rename), 0) != 0) {
        fprintf(stderr, "Failed to add rename rule\n");
        seccomp_release(ctx);
        return false;
    }
    
    // Block renameat syscall
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(renameat), 0) != 0) {
        fprintf(stderr, "Failed to add renameat rule\n");
        seccomp_release(ctx);
        return false;
    }
    
    if (seccomp_load(ctx) != 0) {
        fprintf(stderr, "Failed to load seccomp filter\n");
        seccomp_release(ctx);
        return false;
    }
    
    printf("Applied restrictive seccomp policy\n");
    seccomp_release(ctx);
    return true;
}