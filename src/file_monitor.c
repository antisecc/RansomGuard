// file_monitor.c
#include "file_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <string.h>
#include <errno.h>  

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
    
    return true;
}

void start_file_monitoring(void) {
    if (!keep_running) {
        return;
    }
    
    char buffer[EVENT_BUF_LEN];
    int length;

    length = read(fd, buffer, EVENT_BUF_LEN);
    if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return;
    }
    
    if (length < 0) {
        perror("read");
        return;
    }
    
    // Proc events
    int i = 0;
    printf("Monitoring directory: %s\n", target_path);
    

    i = 0;
    while (i < length) {
        struct inotify_event *event = (struct inotify_event*)&buffer[i];
        
        if (event->len) {
            if (event->mask & IN_CREATE) {
                printf("File created: %s\n", event->name);
            } else if (event->mask & IN_DELETE) {
                printf("File deleted: %s\n", event->name);
            } else if (event->mask & IN_MODIFY) {
                printf("File modified: %s\n", event->name);
            } else if (event->mask & IN_MOVED_FROM) {
                printf("File moved from: %s\n", event->name);
            } else if (event->mask & IN_MOVED_TO) {
                printf("File moved to: %s\n", event->name);
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