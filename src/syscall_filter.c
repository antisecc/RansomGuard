// syscall_filter.c
#include "syscall_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/syscall.h>

bool init_syscall_filter() {
    // Create seccomp context
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
    
    // Add rules to block dangerous syscalls or limit them
    
    // Block unlink syscall (file deletion)
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(unlink), 0) != 0) {
        fprintf(stderr, "Failed to add unlink rule\n");
        seccomp_release(ctx);
        return false;
    }
    
    // Block unlinkat syscall (another way to delete files)
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(unlinkat), 0) != 0) {
        fprintf(stderr, "Failed to add unlinkat rule\n");
        seccomp_release(ctx);
        return false;
    }
    
    // Block rename syscall
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
    
    // Load the filter
    if (seccomp_load(ctx) != 0) {
        fprintf(stderr, "Failed to load seccomp filter\n");
        seccomp_release(ctx);
        return false;
    }
    
    printf("Applied restrictive seccomp policy\n");
    seccomp_release(ctx);
    return true;
}