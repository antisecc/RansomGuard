// entropy_analysis.h

#ifndef ENTROPY_ANALYSIS_H
#define ENTROPY_ANALYSIS_H

#include <stdlib.h>

/**
 * Calculate Shannon entropy of a file's content
 * Returns a value between 0.0 (completely uniform) and 1.0 (completely random)
 * Encrypted files typically have entropy > 0.8
 * 
 * @param filepath Path to the file to analyze
 * @return Normalized entropy value between 0.0 and 1.0
 */
double calculate_file_entropy(const char *filepath);

/**
 * Calculate Shannon entropy of a buffer's content
 * 
 * @param data Pointer to the data buffer
 * @param size Size of the data buffer
 * @return Normalized entropy value between 0.0 and 1.0
 */
double calculate_buffer_entropy(const unsigned char *data, size_t size);

#endif 