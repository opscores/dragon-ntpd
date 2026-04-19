#include "ntpd.h"

ServerConfig *g_servers = NULL;
int g_server_count = 0;
NtpSample g_samples[MAX_SAMPLES];
int g_sample_count = 0;

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

    /* Очистка mode handler */
    mode_handler_cleanup();

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
        syslog(LOG_WARNING, "Конфигурационный файл не найден: %s", config_path);
        return 0;
    }

    char line[256];
    char ip_str[128];
    char port_str[16] = "123";

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == '\r')
            continue;

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

        memset(ip_str, 0, sizeof(ip_str));
        memcpy(ip_str, line, ip_len);

        size_t port_len = strlen(colon + 1);
        if (port_len >= sizeof(port_str) - 1) {
            syslog(LOG_WARNING, "Порт слишком длинный в строке: %s", line);
            continue;
        }
        memset(port_str, 0, sizeof(port_str));
        memcpy(port_str, colon + 1, port_len);

        char *new_ip = strdup(ip_str);
        char *new_port = strdup(port_str);
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

        ServerConfig *temp = realloc(g_servers,
                    (size_t)(g_server_count + 1) * sizeof(ServerConfig));
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
    }

    fclose(fp);
    return g_server_count;
}

int apply_user_privileges(const char *username)
{
    if (username == NULL)
        return 0;

    struct passwd *pw = getpwnam(username);
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

    syslog(LOG_INFO, "Сменили пользователя на: %s (UID=%d, GID=%d)",
           username, (int)pw->pw_uid, (int)pw->pw_gid);
    return 0;
}

static void signal_handler(int sig) {
    (void)sig;
    g_shutdown_requested = 1;
    syslog(LOG_INFO, "Получен сигнал завершения");
}

int main(int argc, char *argv[]) {
    int parse_ret = parse_arguments(argc, argv);

    if (parse_ret == 2) {
        return EXIT_SUCCESS;
    }
    if (parse_ret == 3) {
        return EXIT_SUCCESS;
    }
    if (parse_ret != 0) {
        return EXIT_FAILURE;
    }

    if (g_cli.debug_level > 0) {
        fprintf(stderr, "Debug mode enabled (level %d)\n", g_cli.debug_level);
    }

    atexit(cleanup_resources);

    if (g_cli.foreground || g_cli.debug_level > 0) {
        openlog("dntpd", LOG_PID | LOG_NDELAY, LOG_USER);
    } else {
        openlog("dntpd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
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
            if (apply_user_privileges(g_cli.run_user) != 0) {
                syslog(LOG_ERR, "Не удалось применить привилегии пользователя");
            }
        }
    }

    g_server_count = load_server_config();
    if (g_server_count == 0) {
        syslog(LOG_CRIT, "Не удалось загрузить NTP-серверы. Завершение.");
        closelog();
        return EXIT_FAILURE;
    }

    /* Инициализация mode handler (Security-First) */
    if (mode_handler_init() != 0) {
        syslog(LOG_WARNING, "Ошибка инициализации mode handler");
    }
    mode_handler_parse_config("/etc/time_sync/modes.conf");

    /* Инициализация I-DO state (RFC 5905 Section 8.4) */
    ido_state_init(&g_ido_state);

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