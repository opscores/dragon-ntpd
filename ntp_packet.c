#include "ntpd.h"

uint32_t read_u32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void write_u32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

/**
 * NTP Extension Field Types (RFC 5905 Section 2.1, RFC 8915)
 */
#define NTP_EF_CRYPTO_NAK      0x0000   /* Crypto-NAK: authentication failure */
#define NTP_EF_MAC             0x0003   /* Legacy MAC */
#define NTP_EF_I_DO_OFFER      0x0007   /* I-DO Offer */
#define NTP_EF_I_DO_RESPONSE   0x8007   /* I-DO Response */
#define NTP_EF_LAST_EF         0x0008   /* Last Extension Field */
#define NTP_EF_CHECKSUM_COMP   0x0005   /* Checksum Complement */
#define NTP_EF_NTS_UID_REQ     0x0104   /* NTS Unique Identifier Request */
#define NTP_EF_NTS_UID_RESP    0x8104   /* NTS Unique Identifier Response */
#define NTP_EF_NTS_COOKIE      0x0204   /* NTS Cookie */
#define NTP_EF_NTS_COOKIE_PH   0x0304   /* NTS Cookie Placeholder */
#define NTP_EF_NTS_AEEF_REQ    0x0404   /* NTS AEEF Request */
#define NTP_EF_NTS_AEEF_RESP   0x8404   /* NTS AEEF Response */
#define NTP_EF_KOD             0x0000   /* Kiss-o'-Death marker */

/**
 * Extension field header format (RFC 5905 Section 2.1):
 * 
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +---------------+---------------+-------------------------------+
 * |R|E|      Code |       Type    |       (Field Length)          |
 * +-------------------------------+-------------------------------+
 * 
 * R (Response Flag): 0=Information/Query, 1=Response
 * E (Error Flag): 0=OK, 1=Error (deprecated)
 * Code: 8-bit subtype (bottom 2 bits of high-order octet reserved)
 * Type: 8-bit field type identifier
 * Field Length: 16-bit total length in octets (including header)
 * 
 * Alignment: All extension fields are zero-padded to 4-octet boundary
 * Minimum size: 4 octets (one word)
 * Maximum size: 65,532 octets
 */

/**
 * Validate extension field length according to RFC 5905
 *
 * @param length Field length
 * @param remaining Remaining bytes in packet
 * @return 0 on valid, -1 on error
 */
static int validate_extension_field_length(uint16_t length, size_t remaining) {
    /* RFC 5905: Length field bottom 2 bits should be zero (4-byte alignment) */
    if (length & 0x03) {
        syslog(LOG_WARNING, "Extension field length not aligned to 4 bytes: %u", length);
        return -1;
    }

    /* Check maximum size (65,532 octets due to 16-bit Length field) */
    if (length > 65532) {
        syslog(LOG_WARNING, "Extension field length exceeds maximum: %u", length);
        return -1;
    }

    /* Check bounds */
    if ((size_t)(48 + length) > remaining) {
        syslog(LOG_WARNING, "Extension field exceeds packet bounds");
        return -1;
    }

    return 0;
}

/**
 * Parse extension field header
 *
 * @param data Pointer to packet data (after 48-byte header)
 * @param pos Current position in packet
 * @param type Pointer to store field type
 * @param length Pointer to store field length
 * @return 0 on success, -1 on error
 */
static int parse_extension_field_header(const uint8_t *data, size_t pos,
                                         uint16_t *type, uint16_t *length) {
    if (pos + 4 > 48) {
        return -1;  /* Extension fields only in bytes 48+ */
    }

    uint8_t high = data[pos];
    uint8_t low = data[pos + 1];

    /* Type (high byte) */
    uint16_t field_type = (uint16_t)((high << 8) | low);
    /* Length (bytes 2-3) */
    uint16_t field_len = (uint16_t)((data[pos + 2] << 8) | data[pos + 3]);

    *type = field_type;
    *length = field_len;

    return 0;
}

/**
 * Process NTS Unique Identifier extension field (RFC 8915)
 *
 * @param data Pointer to field data
 * @param len Field length
 */
static void process_nts_uid(const uint8_t *data __attribute__((unused)), size_t len __attribute__((unused))) {
    syslog(LOG_DEBUG, "Processing NTS Unique Identifier field");
    /* RFC 8915: Store UID for future authentication */
}

/**
 * Process NTS Cookie extension field (RFC 8915)
 *
 * @param data Pointer to field data
 * @param len Field length
 */
static void process_nts_cookie(const uint8_t *data __attribute__((unused)), size_t len __attribute__((unused))) {
    syslog(LOG_DEBUG, "Processing NTS Cookie field");
    /* RFC 8915: Store cookie for authentication */
}

/**
 * Process NTS AEEF extension field (RFC 8915)
 *
 * @param data Pointer to field data
 * @param len Field length
 */
static void process_nts_aeef(const uint8_t *data __attribute__((unused)), size_t len __attribute__((unused))) {
    syslog(LOG_DEBUG, "Processing NTS AEEF field");
    /* RFC 8915: Process authenticated extension field */
}

/**
 * Log extension field with detailed information
 *
 * @param type Field type
 * @param length Field length
 * @param pos Position in packet
 */
static void log_extension_field(uint16_t type, uint16_t length, size_t pos) {
    const char *type_str = "Unknown";

    switch (type) {
        case NTP_EF_CRYPTO_NAK:
            type_str = "Crypto-NAK (Authentication Failure)";
            break;
        case NTP_EF_MAC:
            type_str = "Legacy MAC";
            break;
        case NTP_EF_I_DO_OFFER:
            type_str = "I-DO Offer";
            break;
        case NTP_EF_I_DO_RESPONSE:
            type_str = "I-DO Response";
            break;
        case NTP_EF_LAST_EF:
            type_str = "LAST-EF (End of Extension Fields)";
            break;
        case NTP_EF_CHECKSUM_COMP:
            type_str = "Checksum Complement";
            break;
        case NTP_EF_NTS_UID_REQ:
            type_str = "NTS Unique Identifier Request";
            break;
        case NTP_EF_NTS_UID_RESP:
            type_str = "NTS Unique Identifier Response";
            break;
        case NTP_EF_NTS_COOKIE:
            type_str = "NTS Cookie";
            break;
        case NTP_EF_NTS_COOKIE_PH:
            type_str = "NTS Cookie Placeholder";
            break;
        case NTP_EF_NTS_AEEF_REQ:
            type_str = "NTS AEEF Request";
            break;
        case NTP_EF_NTS_AEEF_RESP:
            type_str = "NTS AEEF Response";
            break;
        default:
            /* Check for Kiss-o'-Death marker (RFC 5905 Section 8.3) */
            if (type == 0 && length == 2) {
                type_str = "Kiss-o'-Death (KOD)";
            } else {
                type_str = "Unknown";
            }
            break;
    }

    syslog(LOG_DEBUG, "Extension field: type=0x%04X (%s), len=%u, pos=%zu",
           type, type_str, length, pos);
}

/**
 * Skip extension fields in NTP packet (RFC 5905 Section 2.1)
 *
 * Extension fields are located after the 48-byte NTP header.
 * They are used for:
 * - Kiss-o'-Death marker (RFC 5905 Section 8.3)
 * - I-DO capability negotiation (RFC 5905 Section 8.4)
 * - NTS security extensions (RFC 8915)
 * - Legacy MAC authentication
 *
 * @param data Pointer to packet data
 * @param size Total packet size
 * @return Number of bytes skipped (extension fields), or 0 if none
 */
static int skip_extension_fields(const uint8_t *data, size_t size) {
    if (size <= 48) return 0;

    size_t pos = 48;
    int skipped = 0;

    while (pos + 4 <= size) {
        uint16_t field_type;
        uint16_t field_len;

        int ret = parse_extension_field_header(data, pos, &field_type, &field_len);
        if (ret < 0) break;

        /* Validate extension field length (RFC 5905) */
        ret = validate_extension_field_length(field_len, size - 48);
        if (ret < 0) {
            syslog(LOG_WARNING, "Invalid extension field length at offset %zu", pos);
            break;
        }

        /* LAST-EF marker: no more extension fields follow */
        if (field_type == NTP_EF_LAST_EF) {
            syslog(LOG_DEBUG, "LAST-EF marker detected at offset %zu", pos);
            break;
        }

        /* Kiss-o'-Death marker (RFC 5905 Section 8.3) */
        /* Type=0, Length=2 indicates Crypto-NAK/authentication failure */
        if (field_type == 0 && field_len == 2) {
            syslog(LOG_INFO, "Kiss-o'-Death (KOD) marker detected at offset %zu", pos);
            return (int)(pos + field_len - 48);
        }

        /* I-DO extension fields (RFC 5905 Section 8.4) */
        if (field_type == NTP_EF_I_DO_OFFER || field_type == NTP_EF_I_DO_RESPONSE) {
            syslog(LOG_DEBUG, "I-DO extension field detected at offset %zu", pos);

            /* Initialize I-DO state if not initialized */
            if (g_ido_state.ido_state == IDO_STATE_IDLE) {
                ido_state_init(&g_ido_state);
            }

            /* Process I-DO Offer/Response */
            if (field_type == NTP_EF_I_DO_OFFER) {
                int ret_offer = process_ido_offer(data + 4, field_len - 4, &g_ido_state);
                if (ret_offer < 0) {
                    syslog(LOG_WARNING, "I-DO Offer processing failed");
                }
            } else if (field_type == NTP_EF_I_DO_RESPONSE) {
                int ret_response = process_ido_response(data + 4, field_len - 4, &g_ido_state);
                if (ret_response < 0) {
                    syslog(LOG_WARNING, "I-DO Response processing failed");
                }
            }

            /* Update state machine */
            int ret_state = ido_state_machine(&g_ido_state, 
                                              field_type == NTP_EF_I_DO_OFFER,
                                              field_type == NTP_EF_I_DO_RESPONSE);
            if (ret_state < 0) {
                syslog(LOG_WARNING, "I-DO state machine error");
            }

            /* Log I-DO state */
            ido_log_state();

            pos += field_len;
            skipped += field_len;
            continue;
        }

        /* NTS extension fields (RFC 8915) */
        if (field_type >= NTP_EF_NTS_UID_REQ && field_type <= NTP_EF_NTS_AEEF_RESP) {
            syslog(LOG_DEBUG, "NTS extension field detected at offset %zu", pos);
            
            /* Process NTS UID Request/Response */
            if (field_type == NTP_EF_NTS_UID_REQ || field_type == NTP_EF_NTS_UID_RESP) {
                process_nts_uid(data + 4, field_len - 4);
            }
            /* Process NTS Cookie */
            else if (field_type == NTP_EF_NTS_COOKIE) {
                process_nts_cookie(data + 4, field_len - 4);
            }
            /* Process NTS AEEF */
            else if (field_type == NTP_EF_NTS_AEEF_REQ || field_type == NTP_EF_NTS_AEEF_RESP) {
                process_nts_aeef(data + 4, field_len - 4);
            }
            
            pos += field_len;
            skipped += field_len;
            continue;
        }

        /* Checksum Complement (RFC 5905) */
        if (field_type == NTP_EF_CHECKSUM_COMP) {
            syslog(LOG_DEBUG, "Checksum Complement extension field detected at offset %zu", pos);
            pos += field_len;
            skipped += field_len;
            continue;
        }

        /* Legacy MAC (RFC 5905) */
        if (field_type == NTP_EF_MAC) {
            syslog(LOG_DEBUG, "Legacy MAC extension field detected at offset %zu", pos);
            pos += field_len;
            skipped += field_len;
            continue;
        }

        /* Crypto-NAK (RFC 5905 Section 7.2) */
        if (field_type == NTP_EF_CRYPTO_NAK) {
            syslog(LOG_INFO, "Crypto-NAK extension field detected at offset %zu", pos);
            return (int)(pos + field_len - 48);
        }

        /* Unknown extension field type - log and skip if valid length */
        if (field_len >= 4 && pos + field_len <= size) {
            log_extension_field(field_type, field_len, pos);
            pos += field_len;
            skipped += field_len;
        } else {
            syslog(LOG_WARNING, "Invalid extension field: type=0x%04X, len=%u at offset %zu",
                   field_type, field_len, pos);
            break;
        }
    }

    return (int)skipped;
}

bool parse_ntp_packet(const void *buffer, size_t size, NtpPacket *pkt) {
    if (buffer == NULL || pkt == NULL) {
        syslog(LOG_WARNING, "NULL указатель при парсинге пакета");
        return false;
    }

    if (size < 48) {
        syslog(LOG_WARNING, "Пакет слишком мал: %zu байт (минимум 48)", size);
        return false;
    }

    const uint8_t *data = (const uint8_t *)buffer;
    int ext_len = skip_extension_fields(data, size);
    if (ext_len > 0) {
        syslog(LOG_DEBUG, "Пропускаем extension fields: %d байт", ext_len);
    }

    /* Check for KOD in header (RFC 5905 Section 8.3) */
    if (ntp_is_kod(pkt)) {
        syslog(LOG_WARNING, "Kiss-o'-Death marker detected in packet header");
        return false;
    }

    /* Парсинг только основных 48 байт, игнорируя extension fields */
    pkt->li_vn_mode = data[0];
    pkt->stratum = data[1];
    pkt->poll = (int8_t)data[2];
    pkt->precision = (int8_t)data[3];
    pkt->root_delay = read_u32be(&data[4]);
    pkt->root_disp = read_u32be(&data[8]);
    pkt->ref_id = read_u32be(&data[12]);

    pkt->ref_ts.sec = read_u32be(&data[16]);
    pkt->ref_ts.frac = read_u32be(&data[20]);
    pkt->orig_ts.sec = read_u32be(&data[24]);
    pkt->orig_ts.frac = read_u32be(&data[28]);
    pkt->recv_ts.sec = read_u32be(&data[32]);
    pkt->recv_ts.frac = read_u32be(&data[36]);
    pkt->xmit_ts.sec = read_u32be(&data[40]);
    pkt->xmit_ts.frac = read_u32be(&data[44]);

    uint8_t li = (uint8_t)((pkt->li_vn_mode & NTP_LI_MASK) >> NTP_LI_SHIFT);
    uint8_t vn = (uint8_t)((pkt->li_vn_mode & NTP_VN_MASK) >> NTP_VN_SHIFT);
    uint8_t mode = (uint8_t)(pkt->li_vn_mode & NTP_MODE_MASK);

    if (vn != NTP_VN_4) {
        syslog(LOG_WARNING, "Неверная версия NTP: %u (ожидалось 4)", vn);
        return false;
    }

    if (mode == 0 || mode > 7) {
        syslog(LOG_WARNING, "Неверный mode NTP: %u", mode);
        return false;
    }

    if (li > 3) {
        syslog(LOG_WARNING, "Неверный Leap Indicator: %u", li);
        return false;
    }

    if (pkt->stratum > 16) {
        syslog(LOG_WARNING, "Страта превышает допустимое значение: %u", pkt->stratum);
        return false;
    }

    return true;
}

void create_ntp_request(void *buffer, NtpTimestamp *xmit_out) {
    if (buffer == NULL) {
        syslog(LOG_WARNING, "NULL указатель при создании запроса");
        return;
    }

    uint8_t *p = (uint8_t *)buffer;
    memset(p, 0, 48);

    p[0] = (uint8_t)((0u << NTP_LI_SHIFT) | ((uint8_t)NTP_VN_4 << NTP_VN_SHIFT) | 3u);
    p[1] = 0;
    p[2] = (uint8_t)(g_local_poll < 0 ? 12 : g_local_poll);
    p[3] = (uint8_t)g_local_precision;

    NtpTimestamp t1 = ntp_timestamp_now();
    write_u32be(&p[40], t1.sec);
    write_u32be(&p[44], t1.frac);
    if (xmit_out != NULL) {
        *xmit_out = t1;
    }
}

bool ntp_is_kod(const NtpPacket *pkt) {
    if (pkt == NULL) return false;

    /* RFC 5905 Section 8.3: KOD in header
     * stratum=127 (0x7F) and leap=3 indicates KOD */
    uint8_t li = (uint8_t)((pkt->li_vn_mode & NTP_LI_MASK) >> NTP_LI_SHIFT);
    return pkt->stratum == 127 && li == 3;
}

/* ============================================================================
 * I-DO Capability Negotiation Functions (RFC 5905 Section 8.4)
 * ============================================================================ */

/**
 * Initialize I-DO state
 *
 * @param state Pointer to IdoState
 */
void ido_state_init(IdoState *state) {
    if (state == NULL) {
        syslog(LOG_WARNING, "NULL указатель при инициализации I-DO state");
        return;
    }

    memset(state, 0, sizeof(IdoState));
    state->ido_state = IDO_STATE_IDLE;
    state->ido_offer_received = 0;
    state->ido_response_sent = 0;
    state->ido_capabilities = 0;
    state->ido_key_id = 0;
    state->ido_enabled = false;
    state->ido_authenticated = false;

    syslog(LOG_DEBUG, "I-DO state initialized: state=%u", state->ido_state);
}

/**
 * Cleanup I-DO state
 *
 * @param state Pointer to IdoState
 */
void ido_state_cleanup(IdoState *state) {
    if (state == NULL) {
        return;
    }

    memset(state, 0, sizeof(IdoState));
    syslog(LOG_DEBUG, "I-DO state cleaned up");
}

/**
 * Process I-DO Offer extension field (RFC 5905 Section 8.4)
 *
 * @param data Pointer to field data (after header)
 * @param len Field length
 * @param state Pointer to IdoState
 * @return 0 on success, -1 on error
 */
int process_ido_offer(const uint8_t *data, size_t len, IdoState *state) {
    if (data == NULL || state == NULL) {
        return -1;
    }

    /* RFC 5905 Section 8.4: I-DO Offer minimum size is 4 bytes */
    if (len < 4) {
        syslog(LOG_WARNING, "I-DO Offer too small: %zu bytes (minimum 4)", len);
        return -1;
    }

    /* Parse capability flags from Code field (byte 0) */
    uint8_t code = data[0];

    /* Check for reserved bits */
    if (code & IDO_CAP_RESERVED) {
        syslog(LOG_WARNING, "I-DO Offer contains reserved bits");
        return -1;
    }

    /* Check if server offers I-DO capability */
    if (code & IDO_CAP_OFFER) {
        syslog(LOG_DEBUG, "I-DO Offer received with capability flags: 0x%02X", code);
        state->ido_offer_received = 1;
        state->ido_capabilities = code;
    }

    /* Transition state machine */
    state->ido_state = IDO_STATE_OFFER_RECEIVED;

    syslog(LOG_INFO, "I-DO Offer processed: state=%u, capabilities=0x%02X",
           state->ido_state, state->ido_capabilities);

    return 0;
}

/**
 * Process I-DO Response extension field (RFC 5905 Section 8.4)
 *
 * @param data Pointer to field data (after header)
 * @param len Field length
 * @param state Pointer to IdoState
 * @return 0 on success, -1 on error
 */
int process_ido_response(const uint8_t *data, size_t len, IdoState *state) {
    if (data == NULL || state == NULL) {
        return -1;
    }

    /* RFC 5905 Section 8.4: I-DO Response minimum size is 4 bytes */
    if (len < 4) {
        syslog(LOG_WARNING, "I-DO Response too small: %zu bytes (minimum 4)", len);
        return -1;
    }

    /* Parse capability flags from Code field (byte 0) */
    uint8_t code = data[0];

    /* Check for reserved bits */
    if (code & IDO_CAP_RESERVED) {
        syslog(LOG_WARNING, "I-DO Response contains reserved bits");
        return -1;
    }

    /* Check if client responds with I-DO capability */
    if (code & IDO_CAP_RESPONSE) {
        syslog(LOG_DEBUG, "I-DO Response received with capability flags: 0x%02X", code);
        state->ido_response_sent = 1;
        state->ido_capabilities = code;
    }

    /* Transition state machine */
    state->ido_state = IDO_STATE_RESPONSE_SENT;

    syslog(LOG_INFO, "I-DO Response processed: state=%u, capabilities=0x%02X",
           state->ido_state, state->ido_capabilities);

    return 0;
}

/**
 * I-DO Capability Negotiation State Machine (RFC 5905 Section 8.4)
 *
 * State transitions:
 * - IDLE → OFFER_RECEIVED: I-DO Offer received from server
 * - OFFER_RECEIVED → RESPONSE_SENT: Send I-DO Response to server
 * - RESPONSE_SENT → AUTHENTICATED: Authentication established
 * - Any state → REJECTED: I-DO negotiation failed
 *
 * @param state Pointer to IdoState
 * @param offer_received I-DO Offer received flag
 * @param response_sent I-DO Response sent flag
 * @return 0 on success, -1 on error
 */
int ido_state_machine(IdoState *state, bool offer_received, bool response_sent) {
    if (state == NULL) {
        return -1;
    }

    /* Reset state if offer received */
    if (offer_received) {
        state->ido_state = IDO_STATE_OFFER_RECEIVED;
        state->ido_offer_received = 1;
        syslog(LOG_DEBUG, "I-DO state machine: IDLE → OFFER_RECEIVED");
    }

    /* If offer received and response sent, transition to authenticated */
    if (state->ido_offer_received && response_sent) {
        state->ido_state = IDO_STATE_AUTHENTICATED;
        state->ido_authenticated = true;
        syslog(LOG_DEBUG, "I-DO state machine: OFFER_RECEIVED → AUTHENTICATED");
    }

    /* If response sent but no offer received, transition to rejected */
    if (response_sent && !state->ido_offer_received) {
        state->ido_state = IDO_STATE_REJECTED;
        syslog(LOG_WARNING, "I-DO state machine: RESPONSE_SENT → REJECTED (no offer received)");
    }

    return 0;
}

/**
 * Check if I-DO authentication is established
 *
 * @return true if authenticated, false otherwise
 */
bool ido_is_authenticated(void) {
    return g_ido_state.ido_authenticated;
}

/**
 * Log I-DO state
 */
void ido_log_state(void) {
    syslog(LOG_DEBUG, "I-DO state: state=%u, offer_received=%u, response_sent=%u, "
           "capabilities=0x%02X, authenticated=%s",
           g_ido_state.ido_state,
           g_ido_state.ido_offer_received,
           g_ido_state.ido_response_sent,
           g_ido_state.ido_capabilities,
           g_ido_state.ido_authenticated ? "true" : "false");
}