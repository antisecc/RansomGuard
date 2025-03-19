// entropy_analysis.c

#include "entropy_analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>

#define BUFFER_SIZE 4096
#define BYTE_RANGE 256
#define HIGH_ENTROPY_THRESHOLD 7.5
#define MAX_ENTROPY_TRACKED_FILES 100
#define ENTROPY_TRACKING_WINDOW 30  // 30 seconds

// track high-entropy files 
typedef struct {
    time_t timestamp;
    char filepath[PATH_MAX];
    double entropy;
} entropy_event_t;

// Ring buffer to tracking high-entropy file modifications
static entropy_event_t high_entropy_events[MAX_ENTROPY_TRACKED_FILES];
static int entropy_event_count = 0;
static int entropy_event_index = 0;

// Shannon entropy 
double calculate_file_entropy(const char *filepath) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        return 0.0;
    }
    
    // byte freq
    unsigned long byte_count[BYTE_RANGE] = {0};
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    unsigned long total_bytes = 0;
    
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            byte_count[buffer[i]]++;
            total_bytes++;
        }
    }
    
    fclose(file);
    
    if (total_bytes == 0) {
        return 0.0;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < BYTE_RANGE; i++) {
        if (byte_count[i] > 0) {
            double probability = (double)byte_count[i] / total_bytes;
            entropy -= probability * log2(probability);
        }
    }
    
    entropy /= 8.0;
    
    return entropy;
}

// Buffer entropy
double calculate_buffer_entropy(const unsigned char *data, size_t size) {
    if (!data || size == 0) {
        return 0.0;
    }
    
    unsigned long byte_count[BYTE_RANGE] = {0};
    
    for (size_t i = 0; i < size; i++) {
        byte_count[data[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < BYTE_RANGE; i++) {
        if (byte_count[i] > 0) {
            double probability = (double)byte_count[i] / size;
            entropy -= probability * log2(probability);
        }
    }
    
    entropy /= 8.0;
    
    return entropy;
}

/**
 * Calculate Shannon entropy of a file with non-blocking I/O
 *
 * @param filepath Path to the file
 * @param timeout_ms Maximum time to spend reading the file (in milliseconds)
 * @return The calculated entropy value (0.0-8.0) or negative on error
 */
double calculate_entropy(const char *filepath, int timeout_ms) {
    if (!filepath) {
        return -1.0;
    }
    
    int fd = open(filepath, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        return -1.0;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1.0;
    }
    
    const off_t max_size = 10 * 1024 * 1024; // 10 MB
    if (st.st_size > max_size) {
        unsigned long byte_count[BYTE_RANGE] = {0};
        unsigned char buffer[BUFFER_SIZE];
        size_t bytes_read;
        unsigned long total_bytes = 0;
        
        bytes_read = read(fd, buffer, BUFFER_SIZE);
        if (bytes_read > 0) {
            for (size_t i = 0; i < bytes_read; i++) {
                byte_count[buffer[i]]++;
                total_bytes++;
            }
        }
        
        if (st.st_size > BUFFER_SIZE * 2) {
            lseek(fd, st.st_size / 2, SEEK_SET);
            bytes_read = read(fd, buffer, BUFFER_SIZE);
            if (bytes_read > 0) {
                for (size_t i = 0; i < bytes_read; i++) {
                    byte_count[buffer[i]]++;
                    total_bytes++;
                }
            }
        }
        
        if (st.st_size > BUFFER_SIZE) {
            off_t offset = st.st_size - BUFFER_SIZE;
            if (offset < 0) offset = 0;
            lseek(fd, offset, SEEK_SET);
            bytes_read = read(fd, buffer, BUFFER_SIZE);
            if (bytes_read > 0) {
                for (size_t i = 0; i < bytes_read; i++) {
                    byte_count[buffer[i]]++;
                    total_bytes++;
                }
            }
        }
        
        close(fd);
        
        if (total_bytes == 0) {
            return 0.0;
        }
        
        double entropy = 0.0;
        for (int i = 0; i < BYTE_RANGE; i++) {
            if (byte_count[i] > 0) {
                double probability = (double)byte_count[i] / total_bytes;
                entropy -= probability * log2(probability);
            }
        }
        
        return entropy / 8.0;
    }
    
    unsigned long byte_count[BYTE_RANGE] = {0};
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    unsigned long total_bytes = 0;
    
    struct timespec start_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    int elapsed_ms = 0;
    
    while (elapsed_ms < timeout_ms) {
        bytes_read = read(fd, buffer, BUFFER_SIZE);
        
        if (bytes_read > 0) {
            for (size_t i = 0; i < bytes_read; i++) {
                byte_count[buffer[i]]++;
                total_bytes++;
            }
        } else if (bytes_read == 0) {
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000); // 10ms
            } else {
                close(fd);
                return -1.0;
            }
        }
        
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        elapsed_ms = (current_time.tv_sec - start_time.tv_sec) * 1000 + 
                    (current_time.tv_nsec - start_time.tv_nsec) / 1000000;
    }
    
    close(fd);
    
    if (total_bytes == 0) {
        return 0.0;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < BYTE_RANGE; i++) {
        if (byte_count[i] > 0) {
            double probability = (double)byte_count[i] / total_bytes;
            entropy -= probability * log2(probability);
        }
    }
    
    entropy /= 8.0;
    
    if (entropy >= HIGH_ENTROPY_THRESHOLD) {
        track_high_entropy_file(filepath, entropy);
    }
    
    return entropy;
}

void init_entropy_tracking(void) {
    memset(high_entropy_events, 0, sizeof(high_entropy_events));
    entropy_event_count = 0;
    entropy_event_index = 0;
}

void track_high_entropy_file(const char *filepath, double entropy) {
    if (!filepath) {
        return;
    }
    
    // Add to ring buffer
    entropy_event_t *event = &high_entropy_events[entropy_event_index];
    event->timestamp = time(NULL);
    strncpy(event->filepath, filepath, PATH_MAX - 1);
    event->filepath[PATH_MAX - 1] = '\0';
    event->entropy = entropy;
    
    // Update index and count
    entropy_event_index = (entropy_event_index + 1) % MAX_ENTROPY_TRACKED_FILES;
    if (entropy_event_count < MAX_ENTROPY_TRACKED_FILES) {
        entropy_event_count++;
    }
}

int check_high_entropy_pattern(int threshold, int window_seconds) {
    time_t now = time(NULL);
    int count = 0;
    
    for (int i = 0; i < entropy_event_count; i++) {
        if (now - high_entropy_events[i].timestamp <= window_seconds) {
            count++;
        }
    }
    
    return count;
}

void get_high_entropy_summary(char *message, size_t message_size, int limit) {
    if (!message || message_size == 0) {
        return;
    }
    
    time_t now = time(NULL);
    int high_entropy_count = check_high_entropy_pattern(1, ENTROPY_TRACKING_WINDOW);
    
    snprintf(message, message_size, 
             "[ALERT] High entropy pattern detected: %d high-entropy file modifications in %d seconds",
             high_entropy_count, ENTROPY_TRACKING_WINDOW);
    
    if (high_entropy_count > 0 && limit > 0) {
        size_t offset = strlen(message);
        
        if (offset < message_size - 20) {
            strncat(message + offset, " - Recent files: ", message_size - offset);
            offset += 16;
            
            int count = 0;
            for (int i = 0; i < entropy_event_count && count < limit; i++) {
                int idx = (entropy_event_index - i - 1);
                if (idx < 0) idx += MAX_ENTROPY_TRACKED_FILES;
                
                entropy_event_t *event = &high_entropy_events[idx];
                
                if (now - event->timestamp <= ENTROPY_TRACKING_WINDOW) {
                    const char *path = event->filepath;
                    const char *basename = strrchr(path, '/');
                    if (basename) {
                        basename++; // Skip the slash
                    } else {
                        basename = path;
                    }
                    
                    size_t remaining = message_size - offset;
                    if (remaining > strlen(basename) + 30) {
                        if (count > 0) {
                            strncat(message + offset, ", ", remaining);
                            offset += 2;
                            remaining -= 2;
                        }
                        
                        char file_info[PATH_MAX + 20];
                        snprintf(file_info, sizeof(file_info), "%s (%.2f)", 
                                basename, event->entropy);
                                
                        strncat(message + offset, file_info, remaining);
                        offset += strlen(file_info);
                    } else {
                        break;
                    }
                    count++;
                }
            }
        }
    }
}

double analyze_file_entropy(const char *filepath) {
    double entropy = calculate_entropy(filepath, 500);
    
    if (entropy >= HIGH_ENTROPY_THRESHOLD) {
        int high_entropy_count = check_high_entropy_pattern(5, ENTROPY_TRACKING_WINDOW);
        
        if (high_entropy_count >= 5) {
            char message[1024];
            get_high_entropy_summary(message, sizeof(message), 3);
            log_suspicious_activity(message);
        }
    }
    
    return entropy;
}

bool init_entropy_analysis(void) {
    init_entropy_tracking();
    return true;
}