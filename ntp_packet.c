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
            pos += field_len;
            skipped += field_len;
            continue;
        }

        /* NTS extension fields (RFC 8915) */
        if (field_type >= NTP_EF_NTS_UID_REQ && field_type <= NTP_EF_NTS_AEEF_RESP) {
            syslog(LOG_DEBUG, "NTS extension field detected at offset %zu", pos);
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
    return pkt->stratum == 0 && pkt->ref_ts.sec == 0 && pkt->ref_ts.frac == 0;
}