#ifndef NTP_PACKET_H
#define NTP_PACKET_H

#include "ido.h"
#include "ntpd.h"
#include <stdint.h>

/* ============================================================================
 * NTP Packet Parsing Functions (RFC 5905 Section 7.3)
 * ============================================================================
 */

bool parse_ntp_packet(const void* buffer, size_t size, NtpPacket* pkt);
void create_ntp_request(void* buffer, NtpTimestamp* xmit_out);
bool ntp_is_kod(const NtpPacket* pkt);

/* Note: I-DO functions are declared in ido.h (included above) */

/* ============================================================================
 * Utility Functions
 * ============================================================================
 */

uint32_t read_u32be(const uint8_t* p);
void write_u32be(uint8_t* p, uint32_t v);

#endif /* NTP_PACKET_H */
