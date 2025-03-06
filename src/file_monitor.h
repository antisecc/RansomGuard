// file_monitor.h
#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include <stdbool.h>
bool init_file_monitor(const char *watch_path);
void start_file_monitoring();
void cleanup_file_monitor();

#endif