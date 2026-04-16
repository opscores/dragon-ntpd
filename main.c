#include "ntpd.h"

ServerConfig *g_servers = NULL;
int g_server_count = 0;
NtpSample g_samples[MAX_SAMPLES];
int g_sample_count = 0;

bool g_time_synced = false;
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

void cleanup_resources(void) {
    syslog(LOG_INFO, "Очистка ресурсов...");

    /* Остановка потока коррекции часов */
    stop_clock_thread();
    cleanup_clock_thread();

    /* Остановка потока обработки пэеров */
    stop_peer_thread();
    cleanup_peer_thread();

    if (g_cli.pid_file != NULL) {
        if (unlink(g_cli.pid_file) == 0) {
            syslog(LOG_INFO, "PID файл удалён: %s", g_cli.pid_file);
        }
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
    const char *config_path = g_cli.config_file ? g_cli.config_file : CONFIG_FILE;
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        syslog(LOG_WARNING, "Файл конфигурации не найден: %s", config_path);
        return 0;
    }

    char line[256];
    char ip_str[128];
    char port_str[16] = "123";

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == '\r') continue;

        char *colon = strchr(line, ':');
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
        strncpy(ip_str, line, ip_len);
        ip_str[ip_len] = '\0';

        size_t port_len = strlen(colon + 1);
        if (port_len >= sizeof(port_str) - 1) {
            syslog(LOG_WARNING, "Порт слишком длинный в строке: %s", line);
            continue;
        }
        strncpy(port_str, colon + 1, sizeof(port_str) - 1);
        port_str[sizeof(port_str) - 1] = '\0';

        g_server_count++;
        void *temp = realloc(g_servers, (size_t)g_server_count * sizeof(ServerConfig));
        if (temp == NULL) {
            syslog(LOG_CRIT, "Ошибка выделения памяти для списка серверов");
            fclose(fp);
            return 0;
        }
        g_servers = (ServerConfig *)temp;

        pthread_mutex_lock(&g_mutex);
        g_servers[g_server_count - 1].ip = strdup(ip_str);
        g_servers[g_server_count - 1].port = strdup(port_str);
        g_servers[g_server_count - 1].next_allowed_sync = 0;

        if (!g_servers[g_server_count - 1].ip || !g_servers[g_server_count - 1].port) {
            syslog(LOG_CRIT, "Ошибка выделения памяти для IP/Port");
            fclose(fp);
            pthread_mutex_unlock(&g_mutex);
            return 0;
        }
        pthread_mutex_unlock(&g_mutex);

        syslog(LOG_INFO, "Конфигурация загружена: %s:%s", ip_str, port_str);
    }

    fclose(fp);
    return g_server_count;
}

void signal_handler(int sig) {
    syslog(LOG_INFO, "Получен сигнал %d, завершение...", sig);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        }
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
            print_version();
            exit(EXIT_SUCCESS);
        }
    }

    if (parse_arguments(argc, argv) != 0) {
        return EXIT_FAILURE;
    }

    if (g_cli.debug_level > 0) {
        fprintf(stderr, "Debug mode enabled (level %d)\n", g_cli.debug_level);
    }

    atexit(cleanup_resources);

    if (g_cli.foreground || g_cli.debug_level > 0) {
        openlog("ntpd", LOG_PID | LOG_NDELAY, LOG_USER);
    } else {
        openlog("ntpd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    if (g_cli.log_file != NULL) {
        FILE *log_fp = fopen(g_cli.log_file, "a");
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
    syslog(LOG_INFO, "System precision: %d (2^%d = %.3f сек)",
            g_local_precision, g_local_precision,
            g_local_precision >= 0 ? (double)(1 << g_local_precision) :
                                     (double)1.0 / (double)(1LL << (-g_local_precision)));

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
            FILE *pid_fp = fopen(g_cli.pid_file, "w");
            if (pid_fp != NULL) {
                fprintf(pid_fp, "%d\n", (int)getpid());
                fclose(pid_fp);
                syslog(LOG_INFO, "PID файл записан: %s (PID=%d)", g_cli.pid_file, (int)getpid());
            } else {
                syslog(LOG_WARNING, "Не удалось записать PID файл: %s: %s", g_cli.pid_file, strerror(errno));
            }
        }

        if (g_cli.run_user != NULL) {
            struct passwd *pw = getpwnam(g_cli.run_user);
            if (pw != NULL) {
                if (setgid(pw->pw_gid) != 0) {
                    syslog(LOG_ERR, "Не удалось setgid(%s): %s", g_cli.run_user, strerror(errno));
                } else if (setuid(pw->pw_uid) != 0) {
                    syslog(LOG_ERR, "Не удалось setuid(%s): %s", g_cli.run_user, strerror(errno));
                } else {
                    syslog(LOG_INFO, "Сменили пользователя на: %s (UID=%d, GID=%d)",
                         g_cli.run_user, (int)pw->pw_uid, (int)pw->pw_gid);
                }
            } else {
                syslog(LOG_ERR, "Пользователь не найден: %s", g_cli.run_user);
            }
        }
    } else {
        if (g_cli.run_user != NULL) {
            struct passwd *pw = getpwnam(g_cli.run_user);
            if (pw != NULL) {
                if (setgid(pw->pw_gid) != 0) {
                    syslog(LOG_ERR, "Не удалось setgid(%s): %s", g_cli.run_user, strerror(errno));
                } else if (setuid(pw->pw_uid) != 0) {
                    syslog(LOG_ERR, "Не удалось setuid(%s): %s", g_cli.run_user, strerror(errno));
                } else {
                    syslog(LOG_INFO, "Сменили пользователя на: %s (UID=%d, GID=%d)",
                         g_cli.run_user, (int)pw->pw_uid, (int)pw->pw_gid);
                }
            } else {
                syslog(LOG_ERR, "Пользователь не найден: %s", g_cli.run_user);
            }
        }
    }

    g_server_count = load_server_config();
    if (g_server_count == 0) {
        syslog(LOG_CRIT, "Не удалось загрузить NTP-серверы. Завершение.");
        closelog();
        return EXIT_FAILURE;
    }

    syslog(LOG_NOTICE, "=====================================================================");
    int sync_interval_1 = g_cli.timeout_sec > 0 ? g_cli.timeout_sec : SYNC_INTERVAL_SECONDS;
    syslog(LOG_NOTICE, "Сервер NTP запущен. Обнаружено %d серверов. Интервал: %d сек.",
            g_server_count, sync_interval_1);
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
        if (start_peer_thread(peer_sock, "0.0.0.0", "123", NULL) != 0) {
            syslog(LOG_CRIT, "Не удалось запустить поток обработки пэеров");
            close_socket(peer_sock);
        } else {
            syslog(LOG_INFO, "Поток обработки пэеров запущен (сокет %d)", peer_sock);
        }
    } else {
        syslog(LOG_WARNING, "Не удалось создать сокет для потока пэеров");
    }

    while (1) {
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
                g_servers[i].next_allowed_sync = now + 15;
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