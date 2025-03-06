// daemon_utils.c
#include "daemon_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

static char *current_pid_file = NULL;

bool daemonize() {
    pid_t pid;

    // Fork off the parent process
    pid = fork();
    if (pid < 0) {
        return false;
    }
    
    // Exit the parent process
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Create a new session
    if (setsid() < 0) {
        return false;
    }

    // Ignore signal sent from child to parent process
    signal(SIGCHLD, SIG_IGN);

    // Fork off for the second time
    pid = fork();
    if (pid < 0) {
        return false;
    }
    
    // Exit from the first child
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Change the working directory to root
    chdir("/");

    // Close all open file descriptors
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }

    // Reopen standard file descriptors to /dev/null
    int fd = open("/dev/null", O_RDWR);
    dup(fd); // stdout
    dup(fd); // stderr

    return true;
}

bool write_pid_file(const char *pid_file) {
    FILE *fp = fopen(pid_file, "w");
    if (fp == NULL) {
        return false;
    }

    current_pid_file = strdup(pid_file);
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    return true;
}

void remove_pid_file(const char *pid_file) {
    if (pid_file) {
        unlink(pid_file);
    } else if (current_pid_file) {
        unlink(current_pid_file);
        free(current_pid_file);
        current_pid_file = NULL;
    }
}