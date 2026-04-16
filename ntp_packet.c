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

static int skip_extension_fields(const uint8_t *data, size_t size) {
    if (size <= 48) return 0;

    size_t pos = 48;
    while (pos + 4 <= size) {
        uint16_t field_type = (uint16_t)((data[pos] << 8) | data[pos + 1]);
        uint16_t field_len = (uint16_t)((data[pos + 2] << 8) | data[pos + 3]);

        /* Kiss-o'-Death marker: type=0, length=2 (RFC 5905 §2.1) */
        if (field_type == 0 && field_len == 2) {
            syslog(LOG_INFO, "Kiss-o'-Death marker detected at offset %zu", pos);
            return (int)(pos + field_len - 48);
        }

        /* Проверка на корректную длину поля */
        if (field_len < 4 || pos + field_len > size) {
            syslog(LOG_WARNING, "Некорректный extension field: type=%u, len=%u at offset %zu",
                   field_type, field_len, pos);
            break;
        }

        pos += field_len;
    }

    return (int)(pos - 48);
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