// entropy_analysis.h

#ifndef ENTROPY_ANALYSIS_H
#define ENTROPY_ANALYSIS_H
#include <stdbool.h>
#include <stdlib.h>

/**
 * Initialize entropy analysis module
 * @return true on success, false on failure
 */
bool init_entropy_analysis(void);

/**
 * Calculate entropy with timeout
 * @param filepath Path to the file
 * @param timeout_ms Timeout in milliseconds (0 for no timeout)
 * @return Entropy value (0.0-8.0) or -1.0 on error
 */
double calculate_entropy(const char *filepath, int timeout_ms);

/**
 * Check if a file's entropy is suspiciously high
 * @param path Path to the file
 * @return true if entropy is high, false otherwise
 */
bool has_high_entropy(const char *path);

/**
 * Clean up entropy analysis resources
 */
void cleanup_entropy_analysis(void);

/**
 * Calculate file entropy
 * @param filepath Path to the file
 * @return Entropy value (0.0-8.0) or -1.0 on error
 */
double calculate_file_entropy(const char *filepath);

/**
 * Calculate entropy of a memory buffer
 * @param data Buffer to analyze
 * @param size Size of the buffer
 * @return Entropy value (0.0-8.0) or -1.0 on error
 */
double calculate_buffer_entropy(const unsigned char *data, size_t size);

/**
 * Initialize entropy tracking system
 */
bool init_entropy_tracking(void);

/**
 * Track a file with high entropy
 * @param filepath Path to the file
 * @param entropy Entropy value
 */
void track_high_entropy_file(const char *filepath, double entropy);

/**
 * Check for patterns of high entropy files
 * @param threshold Number of high entropy files to trigger an alert
 * @param window_seconds Time window to consider
 * @return Number of high entropy files found in the window
 */
int check_high_entropy_pattern(int threshold, int window_seconds);

/**
 * Get a summary of high entropy files
 * @param message Buffer to store the message
 * @param message_size Size of the message buffer
 * @param limit Maximum number of files to include
 */
void get_high_entropy_summary(char *message, size_t message_size, int limit);

/**
 * Analyze file entropy with default settings
 * @param filepath Path to the file
 * @return Entropy value (0.0-8.0) or -1.0 on error
 */
double analyze_file_entropy(const char *filepath);

/**
 * Clean up resources
 */
void cleanup_entropy_tracking(void);

#endif