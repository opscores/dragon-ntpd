#define _BSD_SOURCE
#include "main.h"
#include "config.h"
#include "filter.h"
#include "ido.h"
#include "leap_second.h"
#include "mode_handler.h"
#include "ntp_algorithms.h"
#include "ntp_packet.h"
#include "ntpd.h"
#include "socket.h"
#include "threads.h"
#include "time_sync.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

ServerConfig* g_servers = NULL;
int g_server_count = 0;
NtpSample g_samples[MAX_SAMPLES];
int g_sample_count = 0;

/* RFC 5905 Section 11.2.1: Multi-server integration - peer pool for Byzantine
 * fault detection */
PeerState g_peer_pool[MAX_PEERS];
int g_peer_pool_count = 0;

bool g_time_synced = false;
static volatile sig_atomic_t g_shutdown_requested = 0;
uint8_t g_local_stratum = 16;
uint32_t g_local_ref_id = 0x4C4F434CUL;
NtpTimestamp g_local_ref_ts = {0, 0};
NtpTimestamp g_last_sync_ts = {0, 0};
uint32_t g_local_root_delay = 0;
uint32_t g_local_root_disp = 0;
uint8_t g_local_li = 3;
time_t g_last_dispersion_update = 0;

int8_t g_local_precision = -20;
int8_t g_local_poll = 4;
int8_t g_peer_poll = 4;

/* I-DO state (RFC 5905 Section 8.4) */
IdoState g_ido_state;

/* Frequency discipline state (RFC 5905 Section 11.3) */
FreqState g_freq_state;

void cleanup_resources(void) {
    syslog(LOG_INFO, "Очистка ресурсов...");

    /* Остановка TCP listener для ntpq */
    stop_tcp_listener();

    /* Остановка потока коррекции часов */
    stop_clock_thread();
    cleanup_clock_thread();

    /* Остановка потока обработки пэеров */
    stop_peer_thread();
    cleanup_peer_thread();

    /* Очистка I-DO state (RFC 5905 Section 8.4) */
    ido_state_cleanup(&g_ido_state);

    /* Очистка leap second state (RFC 5905 Section 11.4) */
    leap_second_cleanup();

    /* Очистка mode handler */
    mode_handler_cleanup();

    /* Сохранение frequency state (RFC 5905 Section 11.3) */
    save_frequency_persistent();

    if (g_cli.pid_file != NULL) {
        if (unlink(g_cli.pid_file) == 0) { syslog(LOG_INFO, "PID файл удалён: %s", g_cli.pid_file); }
    }

    if (g_server_count > 0 && g_servers != NULL) {
        for (int i = 0; i < g_server_count; i++) {
            free(g_servers[i].ip);
            free(g_servers[i].port);
        }
        free(g_servers);
        g_servers = NULL;
        g_server_count = 0;
    }

    syslog(LOG_INFO, "Ресурсы очищены");
}

int load_server_config(void) {
    const char* config_path = g_cli.config_file ? g_cli.config_file : CONFIG_FILE;
    FILE* fp = fopen(config_path, "r");
    if (!fp) {
        syslog(LOG_WARNING, "Config file not found: %s", config_path);
        return 0;
    }

    char line[256];
    char ip_str[128];
    char port_str[16] = "123";

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == '\r') continue;

        /* Broadcast configuration parsing */
        if (strncmp(line, "enable_broadcast", 16) == 0) {
            char* eq = strchr(line, '=');
            if (eq != NULL) {
                int val = (int)strtol(eq + 1, NULL, 10);
                if (val == 1) {
                    g_cli.broadcast_mode = 1;
                    syslog(LOG_INFO, "Broadcast mode enabled from config");
                }
            }
            continue;
        } else if (strncmp(line, "broadcast_addr", 14) == 0) {
            char* eq = strchr(line, '=');
            if (eq != NULL && strlen(eq + 1) > 1) {
                size_t len = strlen(eq + 1);
                while (len > 0 && (eq[1 + len - 1] == '\n' || eq[1 + len - 1] == '\r')) { len--; }
                if (len > 0 && len < INET_ADDRSTRLEN) {
                    free(g_cli.broadcast_addr);
                    g_cli.broadcast_addr = strndup(eq + 1, len);
                    syslog(LOG_INFO, "Broadcast address from config: %s", g_cli.broadcast_addr);
                }
            }
            continue;
        } else if (strncmp(line, "broadcast_interval", 18) == 0) {
            char* eq = strchr(line, '=');
            if (eq != NULL) {
                int val = (int)strtol(eq + 1, NULL, 10);
                if (val >= 32 && val <= 128) {
                    g_cli.broadcast_interval = val;
                    syslog(LOG_INFO, "Broadcast interval from config: %d seconds", val);
                }
            }
            continue;
        }

        char* colon = strchr(line, ':');
        if (!colon) {
            syslog(LOG_WARNING, "Неверный формат строки конфигурации: %s", line);
            continue;
        }

        ptrdiff_t ip_diff = colon - line;
        if (ip_diff <= 0) {
            syslog(LOG_WARNING, "Неверный IP в строке конфигурации: %s", line);
            continue;
        }
        size_t ip_len = (size_t)ip_diff;
        if (ip_len >= sizeof(ip_str) - 1) {
            syslog(LOG_WARNING, "IP-адрес слишком длинный в строке: %s", line);
            continue;
        }

        memset(ip_str, 0, sizeof(ip_str));
        memcpy(ip_str, line, ip_len);

        size_t port_len = strlen(colon + 1);
        if (port_len >= sizeof(port_str) - 1) {
            syslog(LOG_WARNING, "Порт слишком длинный в строке: %s", line);
            continue;
        }
        memset(port_str, 0, sizeof(port_str));
        memcpy(port_str, colon + 1, port_len);

        char* new_ip = strdup(ip_str);
        char* new_port = strdup(port_str);
        if (!new_ip || !new_port) {
            syslog(LOG_CRIT, "Ошибка выделения памяти для IP/Port");
            free(new_ip);
            free(new_port);
            for (int j = 0; j < g_server_count; j++) {
                free(g_servers[j].ip);
                free(g_servers[j].port);
            }
            free(g_servers);
            g_servers = NULL;
            g_server_count = 0;
            fclose(fp);
            return 0;
        }

        ServerConfig* temp = realloc(g_servers, (size_t)(g_server_count + 1) * sizeof(ServerConfig));
        if (!temp) {
            syslog(LOG_CRIT, "Ошибка выделения памяти для списка серверов");
            free(new_ip);
            free(new_port);
            for (int j = 0; j < g_server_count; j++) {
                free(g_servers[j].ip);
                free(g_servers[j].port);
            }
            free(g_servers);
            g_servers = NULL;
            g_server_count = 0;
            fclose(fp);
            return 0;
        }
        g_servers = temp;

        pthread_mutex_lock(&g_mutex);
        g_servers[g_server_count].ip = new_ip;
        g_servers[g_server_count].port = new_port;
        g_servers[g_server_count].next_allowed_sync = 0;
        pthread_mutex_unlock(&g_mutex);

        g_server_count++;
        syslog(LOG_INFO, "Конфигурация загружена: %s:%s", ip_str, port_str);

        /* RFC 5905 Section 11.2.1: Initialize peer pool for Byzantine fault
         * detection */
        pthread_mutex_lock(&g_mutex);
        if (g_peer_pool_count < MAX_PEERS) {
            /* CERT C 3.4.5: Use snprintf for bounds-safe string copy */
            snprintf(g_peer_pool[g_peer_pool_count].ip, sizeof(g_peer_pool[g_peer_pool_count].ip), "%s", ip_str);
            snprintf(g_peer_pool[g_peer_pool_count].port, sizeof(g_peer_pool[g_peer_pool_count].port), "%s", port_str);
            g_peer_pool[g_peer_pool_count].stratum = 16; /* Unsynchronized */
            g_peer_pool[g_peer_pool_count].delay_us = 0;
            g_peer_pool[g_peer_pool_count].offset_us = 0;
            g_peer_pool[g_peer_pool_count].jitter_us = 0;
            g_peer_pool[g_peer_pool_count].root_disp = 0;
            g_peer_pool[g_peer_pool_count].last_update = 0;
            g_peer_pool[g_peer_pool_count].reachable = false;
            g_peer_pool_count++;
            syslog(LOG_DEBUG, "Peer pool initialized: %s:%s (count=%d)", ip_str, port_str, g_peer_pool_count);
        } else {
            syslog(LOG_WARNING, "Peer pool full (max=%d), skipping: %s:%s", MAX_PEERS, ip_str, port_str);
        }
        pthread_mutex_unlock(&g_mutex);
    }

    fclose(fp);
    return g_server_count;
}

int apply_user_privileges(const char* username) {
    if (username == NULL) return 0;

    struct passwd* pw = getpwnam(username);
    if (pw == NULL) {
        syslog(LOG_ERR, "Пользователь не найден: %s", username);
        return -1;
    }

    if (setgid(pw->pw_gid) != 0) {
        syslog(LOG_ERR, "Не удалось setgid(%s): %s", username, strerror(errno));
        return -1;
    }

    if (setuid(pw->pw_uid) != 0) {
        syslog(LOG_ERR, "Не удалось setuid(%s): %s", username, strerror(errno));
        return -1;
    }

    syslog(LOG_INFO, "Сменили пользователя на: %s (UID=%d, GID=%d)", username, (int)pw->pw_uid, (int)pw->pw_gid);
    return 0;
}

static void signal_handler(int sig) {
    (void)sig;
    g_shutdown_requested = 1;
    syslog(LOG_INFO, "Получен сигнал завершения");
}

int main(int argc, char* argv[]) {
    int parse_ret = parse_arguments(argc, argv);

    if (parse_ret == 2) { return EXIT_SUCCESS; }
    if (parse_ret == 3) { return EXIT_SUCCESS; }
    if (parse_ret != 0) { return EXIT_FAILURE; }

    if (g_cli.debug_level > 0) { fprintf(stderr, "Debug mode enabled (level %d)\n", g_cli.debug_level); }

    atexit(cleanup_resources);

    if (g_cli.foreground || g_cli.debug_level > 0) {
        openlog("dntpd", LOG_PID | LOG_NDELAY, LOG_USER);
    } else {
        openlog("dntpd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    if (g_cli.log_file != NULL) {
        FILE* log_fp = fopen(g_cli.log_file, "a");
        if (log_fp != NULL) {
            if (!g_cli.foreground && !g_cli.no_daemonize) {
                int fd = fileno(log_fp);
                if (fd >= 0) {
                    dup2(fd, STDERR_FILENO);
                    close(fd);
                }
            }
            fprintf(stderr, "Log file opened: %s\n", g_cli.log_file);
        } else {
            syslog(LOG_WARNING, "Не удалось открыть log файл: %s: %s", g_cli.log_file, strerror(errno));
        }
    }

    g_local_precision = get_system_precision();
    syslog(LOG_INFO, "System precision: %d (2^%d = %.3f сек)", g_local_precision, g_local_precision,
           g_local_precision >= 0 ? (double)(1 << g_local_precision) : (double)1.0 / (double)(1LL << (-g_local_precision)));

    g_server_count = load_server_config();
    if (g_server_count == 0) {
        const char* cfg_path = g_cli.config_file ? g_cli.config_file : CONFIG_FILE;
        fprintf(stderr, "ERROR: No servers in %s\n", cfg_path);
        closelog();
        return EXIT_FAILURE;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    if (!g_cli.foreground && !g_cli.no_daemonize) {
        setsid();
        umask(0);

        if (g_cli.pid_file != NULL) {
            FILE* pid_fp = fopen(g_cli.pid_file, "w");
            if (pid_fp != NULL) {
                fprintf(pid_fp, "%d\n", (int)getpid());
                fclose(pid_fp);
                syslog(LOG_INFO, "PID файл записан: %s (PID=%d)", g_cli.pid_file, (int)getpid());
            } else {
                syslog(LOG_WARNING, "Не удалось записать PID файл: %s: %s", g_cli.pid_file, strerror(errno));
            }
        }

        if (g_cli.run_user != NULL) {
            if (apply_user_privileges(g_cli.run_user) != 0) { syslog(LOG_ERR, "Не удалось применить привилегии пользователя"); }
        }
    }

    /* Инициализация mode handler (Security-First) */
    if (mode_handler_init() != 0) { syslog(LOG_WARNING, "Ошибка инициализации mode handler"); }
    mode_handler_parse_config(MODES_CONFIG_FILE);

    /* Инициализация I-DO state (RFC 5905 Section 8.4) */
    ido_state_init(&g_ido_state);

    /* Инициализация frequency discipline (RFC 5905 Section 11.3) */
    init_frequency_discipline();
    load_frequency_persistent();

    /* Инициализация leap second handling (RFC 5905 Section 11.4) */
    if (leap_second_init() != 0) {
        syslog(LOG_WARNING, "Ошибка инициализации leap second handling");
    } else {
        syslog(LOG_INFO, "Leap second handling initialized");
    }

    syslog(LOG_NOTICE, "=====================================================================");
    int sync_interval_1 = g_cli.timeout_sec > 0 ? g_cli.timeout_sec : SYNC_INTERVAL_SECONDS;
    syslog(LOG_NOTICE, "Сервер NTP запущен. Обнаружено %d серверов. Интервал: %d сек.", g_server_count, sync_interval_1);
    syslog(LOG_NOTICE, "=====================================================================");

    /* Запуск потока коррекции часов (RFC 5905 Section 5) */
    if (start_clock_thread(sync_interval_1) != 0) {
        syslog(LOG_CRIT, "Не удалось запустить поток коррекции часов");
    } else {
        syslog(LOG_INFO, "Поток коррекции часов запущен (интервал %d сек)", sync_interval_1);
    }

    /* Запуск потока обработки пэеров (RFC 5905 Section 5) */
    int peer_sock = create_udp_socket(NTP_PORT);
    if (peer_sock >= 0) {
        /* RFC 5905 Section 11.2.1: Multi-server integration - initialize peer pool
         */
        if (start_peer_thread(peer_sock, "0.0.0.0", "123", NULL, 0) != 0) {
            syslog(LOG_CRIT, "Не удалось запустить поток обработки пэеров");
            close_socket(peer_sock);
        } else {
            syslog(LOG_INFO, "Поток обработки пэеров запущен (сокет %d)", peer_sock);
        }
    } else {
        syslog(LOG_WARNING, "Не удалось создать сокет для потока пэеров");
    }

    /* Запуск TCP listener для ntpq (RFC 5905 Section 6) */
    if (start_tcp_listener() >= 0) {
        if (start_ntpq_thread() != 0) {
            syslog(LOG_WARNING, "Не удалось запустить ntpq thread");
            stop_tcp_listener();
        } else {
            syslog(LOG_INFO, "ntpq listener запущен на порту 323");
        }
    } else {
        syslog(LOG_WARNING, "Не удалось создать TCP сокет для ntpq");
    }

    while (!g_shutdown_requested) {
        syslog(LOG_INFO, "--- Начинается цикл синхронизации времени ---");

        bool all_success = true;
        for (int i = 0; i < g_server_count; i++) {
            time_t now = time(NULL);
            if (now < 0) now = 0;

            if (g_servers[i].next_allowed_sync != 0 && now < g_servers[i].next_allowed_sync) {
                all_success = false;
                continue;
            }

            int rc = sync_ntp_time(g_servers[i].ip, g_servers[i].port);
            if (rc != 0) {
                all_success = false;
                g_servers[i].next_allowed_sync = now + SYNC_RETRY_INTERVAL_SEC;
            } else {
                g_servers[i].next_allowed_sync = 0;
            }
        }

        if (all_success) {
            syslog(LOG_NOTICE, "Все попытки синхронизации прошли успешно.");
        } else {
            syslog(LOG_WARNING, "Одна или несколько попыток синхронизации "
                                "завершились ошибкой.");
        }

        int sync_interval_2 = g_cli.timeout_sec > 0 ? g_cli.timeout_sec : SYNC_INTERVAL_SECONDS;
        sleep((unsigned int)sync_interval_2);

        if (g_cli.quit_after_sync) {
            syslog(LOG_NOTICE, "Quit after sync mode - exiting.");
            break;
        }
    }

    closelog();
    return EXIT_SUCCESS;
}
