#ifndef NTPD_MAIN_H
#define NTPD_MAIN_H

/* ============================================================================
 * Server Configuration Functions
 * ============================================================================
 */

int load_server_config(void);
void cleanup_resources(void);
int apply_user_privileges(const char* username);

#endif /* NTPD_MAIN_H */
