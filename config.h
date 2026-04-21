#ifndef NTPD_CONFIG_H
#define NTPD_CONFIG_H

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Type Definitions
 * ============================================================================
 */

typedef struct {
    char* config_file;
    char* pid_file;
    char* log_file;
    char* run_user;
    char* interface;
    int foreground;
    int debug_level;
    int no_daemonize;
    int timeout_sec;
    int quit_after_sync;
    int family_preference;
    int broadcast_mode;
    char* broadcast_addr;
    int broadcast_interval;
} CliConfig;

extern CliConfig g_cli;

/* ============================================================================
 * CLI Functions
 * ============================================================================
 */

void print_usage(const char* prog);
void print_version(void);
int parse_arguments(int argc, char* argv[]);

/* ============================================================================
 * Network Utility Functions
 * ============================================================================
 */

uint16_t nport(uint16_t port);
int npton(uint16_t port, char* buf, size_t buf_size);

#endif /* NTPD_CONFIG_H */
