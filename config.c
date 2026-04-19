/*
 * config.c - Command line argument parsing
 *
 * POSIX-compatible argument parsing with CERT C security compliance
 */

#include "ntpd.h"

#define RET_HELP 2
#define RET_VERSION 3

CliConfig g_cli = {.config_file = CONFIG_FILE,
                   .pid_file = DEFAULT_PID_FILE,
                   .log_file = NULL,
                   .run_user = NULL,
                   .interface = NULL,
                   .foreground = 0,
                   .debug_level = 0,
                   .no_daemonize = 0,
                   .timeout_sec = SYNC_INTERVAL_SECONDS,
                   .quit_after_sync = 0,
                   .family_preference = 0,
                   .broadcast_mode = 0,
                   .broadcast_addr = NULL,
                   .broadcast_interval = 64};

void print_usage(const char* prog) {
    printf("DNTPD v%s - Dragon NTP Server (RFC 5905 compliant)\n\n", VERSION);
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -h, --help         Show this help message\n");
    printf("  -v, --version      Show version information\n");
    printf("  -V, --verbose      Verbose output (same as -v)\n");
    printf("  -c, --config=FILE  Config file path (default: %s)\n", CONFIG_FILE);
    printf("  -f, --foreground   Run in foreground (don't daemonize)\n");
    printf("  -n, --no-daemonize Same as -f (run in foreground)\n");
    printf("  -d, --debug        Enable debug mode\n");
    printf("  -D, --debug=LEVEL  Set debug level (0-%d)\n", MAX_DEBUG_LEVEL);
    printf("  -l, --log=FILE     Log file path\n");
    printf("  -t, --timeout=SEC  Sync timeout in seconds (%d-%d, default: %d)\n", MIN_TIMEOUT_SEC, MAX_TIMEOUT_SEC, SYNC_INTERVAL_SECONDS);
    printf("  -q, --quit         Quit after first sync (testing)\n");
    printf("  -I, --interface=IF Use specific network interface\n");
    printf("  -4, --ipv4        Use IPv4 only (default: dual-stack)\n");
    printf("  -6, --ipv6        Use IPv6 only\n");
    printf("  -b, --broadcast   Enable broadcast mode (RFC 5905)\n");
    printf("  -B, --broadcast-addr=IP  Broadcast address (default: "
           "255.255.255.255)\n");
    printf("  -u, --user=USER    Run as specified user\n");
    printf("  -p, --pid=FILE     PID file path (default: %s)\n", DEFAULT_PID_FILE);
    printf("\n");
}

void print_version(void) {
    printf("dntpd %s - Dragon NTP Server (RFC 5905)\n", VERSION);
    printf("Built: %s %s\n", __DATE__, __TIME__);
}

static int parse_positive_int(const char* str, int min_val, int max_val, int* out) {
    char* endptr = NULL;
    long val;

    if (str == NULL || *str == '\0') return -1;

    errno = 0;
    val = strtol(str, &endptr, 10);

    if (endptr == str || errno != 0) return -1;

    if (val < min_val || val > max_val) return -1;

    *out = (int)val;
    return 0;
}

int parse_arguments(int argc, char* argv[]) {
    int i = 1;

    while (i < argc) {
        char* arg = argv[i];

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            return RET_HELP;
        }

        if (strcmp(arg, "-v") == 0 || strcmp(arg, "--version") == 0 || strcmp(arg, "-V") == 0 || strcmp(arg, "--verbose") == 0) {
            print_version();
            return RET_VERSION;
        }

        if (strcmp(arg, "-c") == 0 || strcmp(arg, "--config") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                g_cli.config_file = argv[++i];
            } else {
                fprintf(stderr, "Error: -c requires config file path\n");
                return -1;
            }
        } else if (strncmp(arg, "--config=", 9) == 0) {
            g_cli.config_file = arg + 9;
        } else if (strcmp(arg, "-f") == 0 || strcmp(arg, "--foreground") == 0) {
            if (g_cli.no_daemonize) fprintf(stderr, "Note: -n has no effect (same as -f)\n");
            g_cli.foreground = 1;
        } else if (strcmp(arg, "-n") == 0 || strcmp(arg, "--no-daemonize") == 0) {
            if (g_cli.foreground) fprintf(stderr, "Note: -f has no effect (same as -n)\n");
            g_cli.no_daemonize = 1;
        } else if (strcmp(arg, "-D") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                if (parse_positive_int(argv[i + 1], 0, MAX_DEBUG_LEVEL, &g_cli.debug_level) != 0) {
                    fprintf(stderr, "Error: -D requires 0-%d\n", MAX_DEBUG_LEVEL);
                    return -1;
                }
                i++;
            } else {
                g_cli.debug_level = 1;
            }
        } else if (strncmp(arg, "-D=", 3) == 0) {
            if (parse_positive_int(arg + 3, 0, MAX_DEBUG_LEVEL, &g_cli.debug_level) != 0) {
                fprintf(stderr, "Error: -D= requires 0-%d\n", MAX_DEBUG_LEVEL);
                return -1;
            }
        } else if (strncmp(arg, "--debug=", 8) == 0) {
            if (parse_positive_int(arg + 8, 0, MAX_DEBUG_LEVEL, &g_cli.debug_level) != 0) {
                fprintf(stderr, "Error: --debug= requires 0-%d\n", MAX_DEBUG_LEVEL);
                return -1;
            }
        } else if (strcmp(arg, "-d") == 0 || strcmp(arg, "--debug") == 0) {
            if (g_cli.debug_level > 0) fprintf(stderr, "Note: -d has no effect (-D was set)\n");
            g_cli.debug_level = 1;
        } else if (strcmp(arg, "-l") == 0 || strcmp(arg, "--log") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                g_cli.log_file = argv[++i];
            } else {
                fprintf(stderr, "Error: -l requires log file path\n");
                return -1;
            }
        } else if (strncmp(arg, "--log=", 6) == 0) {
            g_cli.log_file = arg + 6;
        } else if (strcmp(arg, "-t") == 0 || strcmp(arg, "--timeout") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                if (parse_positive_int(argv[i + 1], MIN_TIMEOUT_SEC, MAX_TIMEOUT_SEC, &g_cli.timeout_sec) != 0) {
                    fprintf(stderr, "Error: -t requires %d-%d\n", MIN_TIMEOUT_SEC, MAX_TIMEOUT_SEC);
                    return -1;
                }
                i++;
            } else {
                fprintf(stderr, "Error: -t requires timeout value\n");
                return -1;
            }
        } else if (strncmp(arg, "--timeout=", 10) == 0) {
            if (parse_positive_int(arg + 10, MIN_TIMEOUT_SEC, MAX_TIMEOUT_SEC, &g_cli.timeout_sec) != 0) {
                fprintf(stderr, "Error: --timeout= requires %d-%d\n", MIN_TIMEOUT_SEC, MAX_TIMEOUT_SEC);
                return -1;
            }
        } else if (strcmp(arg, "-I") == 0 || strcmp(arg, "--interface") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                g_cli.interface = argv[++i];
            } else {
                fprintf(stderr, "Error: -I requires interface name\n");
                return -1;
            }
        } else if (strncmp(arg, "--interface=", 12) == 0) {
            g_cli.interface = arg + 12;
        } else if (strcmp(arg, "-u") == 0 || strcmp(arg, "--user") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                g_cli.run_user = argv[++i];
            } else {
                fprintf(stderr, "Error: -u requires username\n");
                return -1;
            }
        } else if (strncmp(arg, "--user=", 8) == 0) {
            g_cli.run_user = arg + 8;
        } else if (strcmp(arg, "-p") == 0 || strcmp(arg, "--pid") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                g_cli.pid_file = argv[++i];
            } else {
                fprintf(stderr, "Error: -p requires pid file path\n");
                return -1;
            }
        } else if (strncmp(arg, "--pid=", 6) == 0) {
            g_cli.pid_file = arg + 6;
        } else if (strcmp(arg, "-4") == 0 || strcmp(arg, "--ipv4") == 0) {
            if (g_cli.family_preference == 2) {
                fprintf(stderr, "Error: -4 and -6 are mutually exclusive\n");
                return -1;
            }
            g_cli.family_preference = 1;
        } else if (strcmp(arg, "-6") == 0 || strcmp(arg, "--ipv6") == 0) {
            if (g_cli.family_preference == 1) {
                fprintf(stderr, "Error: -4 and -6 are mutually exclusive\n");
                return -1;
            }
            g_cli.family_preference = 2;
        } else if (strcmp(arg, "-b") == 0 || strcmp(arg, "--broadcast") == 0) {
            g_cli.broadcast_mode = 1;
        } else if (strncmp(arg, "-B=", 3) == 0) {
            free(g_cli.broadcast_addr);
            g_cli.broadcast_addr = strndup(arg + 3, INET_ADDRSTRLEN - 1);
        } else if (strncmp(arg, "--broadcast-addr=", 17) == 0) {
            free(g_cli.broadcast_addr);
            g_cli.broadcast_addr = strndup(arg + 17, INET_ADDRSTRLEN - 1);
        } else if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quit") == 0) {
            g_cli.quit_after_sync = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", arg);
            print_usage(argv[0]);
            return -1;
        }

        i++;
    }

    return 0;
}
