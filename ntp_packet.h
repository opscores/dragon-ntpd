#ifndef NTP_PACKET_H
#define NTP_PACKET_H

#include "ido.h"
#include "ntpd.h"
#include <stdint.h>

/* ============================================================================
 * Extension Field Types (RFC 5905 Section 7.5)
 * ============================================================================
 */

/* Crypto-NAK: authentication failure (RFC 5905 Section 7.2) */
#define NTP_EF_CRYPTO_NAK 0x0000

/* Legacy MAC authentication (RFC 5905) */
#define NTP_EF_MAC 0x0003

/* I-DO Offer/Response (RFC 5905 Section 8.4) */
#define NTP_EF_I_DO_OFFER 0x0007    /* I-DO Offer */
#define NTP_EF_I_DO_RESPONSE 0x8007 /* I-DO Response */

/* LAST-EF marker (RFC 5905) */
#define NTP_EF_LAST_EF 0x0008

/* Checksum Complement (RFC 5905) */
#define NTP_EF_CHECKSUM_COMP 0x0005

/* NTS Unique Identifier Request (RFC 8915) */
#define NTP_EF_NTS_UID_REQ 0x0104

/* NTS Unique Identifier Response (RFC 8915) */
#define NTP_EF_NTS_UID_RESP 0x8104

/* NTS Cookie (RFC 8915) */
#define NTP_EF_NTS_COOKIE 0x0204

/* NTS Cookie Placeholder (RFC 8915) */
#define NTP_EF_NTS_COOKIE_PH 0x0304

/* NTS AEEF Request (RFC 8915) */
#define NTP_EF_NTS_AEEF_REQ 0x0404

/* NTS AEEF Response (RFC 8915) */
#define NTP_EF_NTS_AEEF_RESP 0x8404

/* Autokey Offer/Response (RFC 5906) */
#define NTP_EF_AUTOKEY_OFFER 0x000A    /* Autokey Offer */
#define NTP_EF_AUTOKEY_RESPONSE 0x800A /* Autokey Response */

/* Autokey Key Install (RFC 5906) */
#define NTP_EF_AUTOKEY_KEY_INSTALL 0x000B /* Key Install */

/* Autokey Key Rotate (RFC 5906) */
#define NTP_EF_AUTOKEY_KEY_ROTATE 0x000C /* Key Rotate */

/* Autokey Key Revoke (RFC 5906) */
#define NTP_EF_AUTOKEY_KEY_REVOKE 0x000D /* Key Revoke */

/* Kiss-o'-Death marker (RFC 5905 Section 8.3) */
/* Type=0, Length=2 indicates Crypto-NAK/authentication failure */
#define NTP_EF_KOD_MARKER 0x0000

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
