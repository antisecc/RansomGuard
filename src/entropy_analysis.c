// entropy_analysis.c

#include "entropy_analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define BUFFER_SIZE 4096
#define BYTE_RANGE 256

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