/**
 * whitelist.h - Manages process whitelisting to reduce false positives
 */

#ifndef WHITELIST_H
#define WHITELIST_H

#include <stdbool.h>
#include <sys/types.h>

/**
 * Initialize the whitelist from configuration
 * @param config_file Path to configuration file or NULL for default
 * @return true on success, false on failure
 */
bool init_whitelist(const char *config_file);

/**
 * Check if a process is whitelisted
 * @param pid Process ID to check
 * @param exec_path Executable path (optimization to avoid duplicate lookups)
 * @return true if whitelisted, false if not
 */
bool is_process_whitelisted(pid_t pid, const char *exec_path);

/**
 * Add a process or path pattern to the whitelist
 * @param pattern Process name or path pattern to whitelist
 * @return true on success, false on failure
 */
bool add_to_whitelist(const char *pattern);

/**
 * Clean up whitelist resources
 */
void cleanup_whitelist(void);

#endif /* WHITELIST_H */