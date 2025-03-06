// process_analyzer.h
#ifndef PROCESS_ANALYZER_H
#define PROCESS_ANALYZER_H

#include <stdbool.h>
#include <sys/types.h>

bool init_process_analyzer(pid_t target_pid);

void analyze_process();

void cleanup_process_analyzer();

#endif