#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>  // Add this for bool type

// Log levels
typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
} log_level_t;

// Initialize the logger
bool init_logger(int verbosity_level);

// Log a message with specified level
void log_message(log_level_t level, const char *message);

// Log an error message with format string
void log_error(const char *format, ...);

// Log a warning message
void log_warning(const char *message);

// Log suspicious activity
void log_suspicious_activity(const char *message);

// Clean up the logger
void cleanup_logger(void);

#endif /* LOGGER_H */