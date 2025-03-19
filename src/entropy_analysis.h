// entropy_analysis.h

#ifndef ENTROPY_ANALYSIS_H
#define ENTROPY_ANALYSIS_H

#include <stdlib.h>

double calculate_file_entropy(const char *filepath);

double calculate_buffer_entropy(const unsigned char *data, size_t size);

double calculate_entropy(const char *filepath, int timeout_ms);

void init_entropy_tracking(void);

void track_high_entropy_file(const char *filepath, double entropy);

int check_high_entropy_pattern(int threshold, int window_seconds);

void get_high_entropy_summary(char *message, size_t message_size, int limit);

double analyze_file_entropy(const char *filepath);

#endif