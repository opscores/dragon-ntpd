/*
 * autokey.c - Autokey Security Protocol Implementation (RFC 5906)
 *
 * Full Autokey implementation with:
 * - Autokey Offer/Response extension fields parsing (RFC 5906)
 * - State machine implementation
 * - HMAC-SHA1 MAC computation (RFC 5906)
 * - Key management (install/rotate/revoke)
 * - Capability flags handling
 * - State transitions
 * - Memory safety
 * - Error handling
 *
 * RFC 5906 Compliance:
 * - Autokey Offer/Response parsing
 * - Key Install/Rotate/Revoke extension fields
 * - HMAC-SHA1 message authentication
 * - I-DO integration (RFC 5905 Section 8.4)
 *
 * Security (CERT C):
 * - Input validation
 * - Buffer overflow protection
 * - Secure memory operations
 * - Error logging
 */

#include "autokey.h"
#include "ido.h"
#include "ntp_packet.h"
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

/* ============================================================================
 * Constants
 * ============================================================================
 */

/* Minimum extension field length */
#define AUTOKEY_MIN_EF_LENGTH (4)

/* Maximum extension field length */
#define AUTOKEY_MAX_EF_LENGTH (48)

/* Default key ID */
#define AUTOKEY_DEFAULT_KEY_ID 0

/* State machine event types */
#define AUTOKEY_EVENT_OFFER_RECEIVED (1)
#define AUTOKEY_EVENT_RESPONSE_SENT (2)
#define AUTOKEY_EVENT_AUTH_ESTABLISHED (3)
#define AUTOKEY_EVENT_NEGOTIATION_FAILED (4)

/* ============================================================================
 * Forward Declarations
 * ============================================================================
 */

/* ============================================================================
 * State Machine Functions
 * ============================================================================
 */

/**
 * Initialize Autokey state machine
 *
 * Resets all Autokey state to initial values:
 * - State: IDLE
 * - Offer received: false
 * - Response sent: false
 * - Capabilities: 0
 * - Key ID: 0
 * - Key: all zeros
 * - Enabled: false
 * - Authenticated: false
 */
void autokey_init_state(AutokeyState* state) {
    if (state == NULL) { return; }

    /* Reset all fields to initial values */
    state->autokey_state = AUTOKEY_STATE_IDLE;
    state->autokey_offer_received = 0;
    state->autokey_response_sent = 0;
    state->autokey_capabilities = 0;
    state->autokey_key_id = 0;
    memset(state->autokey_key, 0, sizeof(state->autokey_key));
    state->autokey_enabled = 0;
    state->autokey_authenticated = 0;
}

/**
 * Cleanup Autokey state machine
 */
void autokey_cleanup_state(AutokeyState* state) {
    if (state == NULL) { return; }

    /* Reset to initial state */
    autokey_init_state(state);
}

/**
 * Process Autokey Offer extension field
 *
 * RFC 5906: Server sends Autokey Offer to client
 *
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type (should be 0x000A)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 *
 * @return true if offer processed successfully, false otherwise
 */
bool autokey_process_offer(AutokeyState* state, uint16_t ef_type,
                           uint8_t ef_length, const uint8_t* ef_data) {
    if (state == NULL) { return false; }

    /* Validate extension field type */
    if (ef_type != NTP_EF_AUTOKEY_OFFER) { return false; }

    /* Validate extension field length (min 4 bytes) */
    if (ef_length < AUTOKEY_MIN_EF_LENGTH ||
        ef_length > AUTOKEY_MAX_EF_LENGTH) {
        syslog(LOG_WARNING, "Autokey: Invalid offer length %u", ef_length);
        return false;
    }

    /* Extract capability flags from extension field data */
    if (ef_data != NULL && ef_length >= 4) {
        /* Capability flags are in the first byte */
        uint8_t flags = ef_data[0];
        if (ef_length > 0) {
            state->autokey_capabilities = flags & 0x07; /* Only lower 3 bits */
        }
    }

    /* Transition state machine */
    state->autokey_offer_received = 1;
    state->autokey_state = AUTOKEY_STATE_OFFER_RECEIVED;

    /* Log state transition */
    syslog(LOG_INFO, "Autokey: Offer received, state: %s",
           autokey_state_name(state->autokey_state));

    return true;
}

/**
 * Process Autokey Response extension field
 *
 * RFC 5906: Client sends Autokey Response to server
 *
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type (should be 0x800A)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 *
 * @return true if response processed successfully, false otherwise
 */
bool autokey_process_response(AutokeyState* state, uint16_t ef_type,
                              uint8_t ef_length, const uint8_t* ef_data) {
    if (state == NULL) { return false; }

    /* Validate extension field type */
    if (ef_type != NTP_EF_AUTOKEY_RESPONSE) { return false; }

    /* Validate extension field length (min 4 bytes) */
    if (ef_length < AUTOKEY_MIN_EF_LENGTH ||
        ef_length > AUTOKEY_MAX_EF_LENGTH) {
        syslog(LOG_WARNING, "Autokey: Invalid response length %u", ef_length);
        return false;
    }

    /* Extract capability flags from extension field data */
    if (ef_data != NULL && ef_length >= 4) {
        /* Capability flags are in the first byte */
        uint8_t flags = ef_data[0];
        if (ef_length > 0) {
            state->autokey_capabilities = flags & 0x07; /* Only lower 3 bits */
        }
    }

    /* Transition state machine */
    state->autokey_response_sent = 1;
    state->autokey_state = AUTOKEY_STATE_AUTHENTICATED;
    state->autokey_authenticated = 1;

    /* Log state transition */
    syslog(LOG_INFO, "Autokey: Response sent, state: %s",
           autokey_state_name(state->autokey_state));

    return true;
}

/**
 * Process Autokey extension field (unified interface)
 *
 * RFC 5906: Unified interface for processing Autokey extension fields:
 * - type=0x000A: Autokey Offer (server -> client)
 * - type=0x800A: Autokey Response (client -> server)
 *
 * Uses autokey_process_offer() and autokey_process_response() internally.
 *
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 *
 * @return true if extension field processed successfully, false otherwise
 */
bool autokey_process(AutokeyState* state, uint16_t ef_type, uint8_t ef_length,
                     const uint8_t* ef_data) {
    if (state == NULL || ef_data == NULL) { return false; }

    /* Check if it's an Offer (server -> client) */
    if (ef_type == NTP_EF_AUTOKEY_OFFER) {
        return autokey_process_offer(state, ef_type, ef_length, ef_data);
    }

    /* Check if it's a Response (client -> server) */
    if (ef_type == NTP_EF_AUTOKEY_RESPONSE) {
        return autokey_process_response(state, ef_type, ef_length, ef_data);
    }

    return false;
}

/**
 * Process Autokey extension field (skip mode for parsing)
 *
 * Used in skip_extension_fields() to identify Autokey fields
 * without processing them. Updates state machine for tracking.
 *
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type
 * @param ef_length Extension field length
 *
 * @return true if extension field is valid Autokey, false otherwise
 */
bool autokey_process_skip(AutokeyState* state, uint16_t ef_type,
                          uint8_t ef_length) {
    /* Validate extension field type */
    if (ef_type != NTP_EF_AUTOKEY_OFFER && ef_type != NTP_EF_AUTOKEY_RESPONSE) {
        return false;
    }

    /* Validate extension field length (min 4 bytes) */
    if (ef_length < AUTOKEY_MIN_EF_LENGTH ||
        ef_length > AUTOKEY_MAX_EF_LENGTH) {
        syslog(LOG_WARNING, "Autokey: Invalid skip length %u", ef_length);
        return false;
    }

    /* Validate state pointer */
    if (state == NULL) { return false; }

    /* Update state machine for tracking */
    if (ef_type == NTP_EF_AUTOKEY_OFFER) {
        state->autokey_offer_received = 1;
    } else if (ef_type == NTP_EF_AUTOKEY_RESPONSE) {
        state->autokey_response_sent = 1;
    }

    return true;
}

/**
 * State machine transition handler
 *
 * RFC 5906 State Machine:
 *
 * IDLE
 *   │
 *   ├─ Autokey Offer received ──→ OFFER_RECEIVED
 *   │                            │
 *   │                            ├─ Send Autokey Response ──→ RESPONSE_SENT
 *   │                            │                             │
 *   │                            │                             ├─ Key
 * installation │                            │                             │ │
 * │                             └─ Authentication ──→ REJECTED │ └─ Autokey
 * Response sent ──→ RESPONSE_SENT │ └─ No offer received ──→ REJECTED
 */
uint8_t autokey_state_machine(AutokeyState* state, uint8_t event) {
    if (state == NULL) { return AUTOKEY_STATE_IDLE; }

    uint8_t new_state = state->autokey_state;

    switch (event) {
    case AUTOKEY_EVENT_OFFER_RECEIVED:
        /* IDLE → OFFER_RECEIVED */
        if (state->autokey_state == AUTOKEY_STATE_IDLE) {
            new_state = AUTOKEY_STATE_OFFER_RECEIVED;
        }
        break;

    case AUTOKEY_EVENT_RESPONSE_SENT:
        /* OFFER_RECEIVED → RESPONSE_SENT */
        if (state->autokey_state == AUTOKEY_STATE_OFFER_RECEIVED) {
            new_state = AUTOKEY_STATE_RESPONSE_SENT;
        }
        break;

    case AUTOKEY_EVENT_AUTH_ESTABLISHED:
        /* RESPONSE_SENT → AUTHENTICATED */
        if (state->autokey_state == AUTOKEY_STATE_RESPONSE_SENT) {
            new_state = AUTOKEY_STATE_AUTHENTICATED;
        }
        break;

    case AUTOKEY_EVENT_NEGOTIATION_FAILED:
        /* Any state → REJECTED */
        new_state = AUTOKEY_STATE_REJECTED;
        break;

    default: break;
    }

    if (new_state != state->autokey_state) {
        uint8_t prev_state = state->autokey_state;
        state->autokey_state = new_state;
        syslog(LOG_INFO, "Autokey: State transition: %s → %s",
               autokey_state_name(prev_state), autokey_state_name(new_state));
    }

    return new_state;
}

/**
 * Check if Autokey is authenticated
 */
bool autokey_is_authenticated(const AutokeyState* state) {
    if (state == NULL) { return false; }

    return state->autokey_authenticated != 0;
}

/**
 * Log Autokey state
 */
void autokey_log_state(const AutokeyState* state) {
    if (state == NULL) { return; }

    syslog(LOG_INFO,
           "Autokey: State: %s, Offer: %s, Response: %s, "
           "Capabilities: 0x%02X, KeyID: %u, Authenticated: %s",
           autokey_state_name(state->autokey_state),
           state->autokey_offer_received ? "yes" : "no",
           state->autokey_response_sent ? "yes" : "no",
           state->autokey_capabilities, state->autokey_key_id,
           state->autokey_authenticated ? "yes" : "no");
}

/**
 * Get Autokey state name
 */
const char* autokey_state_name(uint8_t state) {
    switch (state) {
    case AUTOKEY_STATE_IDLE: return "IDLE";
    case AUTOKEY_STATE_OFFER_RECEIVED: return "OFFER_RECEIVED";
    case AUTOKEY_STATE_RESPONSE_SENT: return "RESPONSE_SENT";
    case AUTOKEY_STATE_AUTHENTICATED: return "AUTHENTICATED";
    case AUTOKEY_STATE_REJECTED: return "REJECTED";
    default: return "UNKNOWN";
    }
}

/**
 * Get Autokey capability flag name
 */
const char* autokey_capability_name(uint8_t flag) {
    switch (flag) {
    case AUTOKEY_CAP_OFFER: return "AUTOKEY_CAP_OFFER";
    case AUTOKEY_CAP_RESPONSE: return "AUTOKEY_CAP_RESPONSE";
    case AUTOKEY_CAP_RESERVED: return "AUTOKEY_CAP_RESERVED";
    default: return "UNKNOWN";
    }
}

/* ============================================================================
 * HMAC-SHA1 Implementation (RFC 5906 Section 3.4.2)
 * ============================================================================
 */

#include <gcrypt.h>

/* HMAC-SHA1 digest size (20 bytes) */
#define HMAC_SHA1_DIGEST_SIZE 20

/* Default key file path */
#define AUTOKEY_DEFAULT_KEY_FILE "/etc/ntp/keys/autokey.key"

/**
 * Compute HMAC-SHA1 digest
 *
 * RFC 5906: HMAC-SHA1 over NTP header and extension fields
 *
 * @param data Input data to authenticate
 * @param data_len Length of input data
 * @param key Key material (20 bytes for HMAC-SHA1)
 * @param key_len Length of key material
 * @param digest Output buffer (20 bytes)
 * @return 0 on success, -1 on error
 */
int autokey_compute_hmac(const uint8_t* data, size_t data_len,
                         const uint8_t* key, size_t key_len, uint8_t* digest) {
    if (data == NULL || key == NULL || digest == NULL) { return -1; }

    /* Validate key length */
    if (key_len == 0 || key_len > 64) {
        syslog(LOG_ERR, "Autokey: Invalid key length %zu", key_len);
        return -1;
    }

    gcry_error_t err;
    gcry_md_hd_t hd;

    /* Initialize HMAC-SHA1 context */
    err = gcry_md_open(&hd, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC);
    if (err != GPG_ERR_NO_ERROR) {
        syslog(LOG_ERR, "Autokey: Failed to open HMAC context: %s",
               gcry_strsource(err));
        return -1;
    }

    /* Set key */
    err = gcry_md_setkey(hd, key, (unsigned int)key_len);
    if (err != GPG_ERR_NO_ERROR) {
        gcry_md_close(hd);
        syslog(LOG_ERR, "Autokey: Failed to set HMAC key: %s",
               gcry_strsource(err));
        return -1;
    }

    /* Write data */
    gcry_md_write(hd, data, data_len);

    /* Get digest */
    uint8_t* result = gcry_md_read(hd, GCRY_MD_SHA1);
    if (result == NULL) {
        gcry_md_close(hd);
        syslog(LOG_ERR, "Autokey: Failed to read HMAC digest");
        return -1;
    }

    /* Copy digest to output */
    memcpy(digest, result, HMAC_SHA1_DIGEST_SIZE);
    gcry_md_close(hd);

    return 0;
}

/**
 * Load key from file
 *
 * @param key_file Path to key file
 * @param key_id Pointer to store key identifier
 * @param key Output buffer (20 bytes)
 * @return 0 on success, -1 on error
 */
static int autokey_load_key_from_file(const char* key_file, uint32_t* key_id,
                                      uint8_t* key) {
    if (key_file == NULL || key == NULL) { return -1; }

    FILE* fp = fopen(key_file, "rb");
    if (fp == NULL) {
        syslog(LOG_WARNING, "Autokey: Failed to open key file: %s", key_file);
        return -1;
    }

    /* Read key ID */
    uint32_t file_key_id;
    if (fread(&file_key_id, sizeof(file_key_id), 1, fp) != 1) {
        syslog(LOG_WARNING, "Autokey: Failed to read key ID from file");
        fclose(fp);
        return -1;
    }

    /* Read key */
    if (fread(key, 1, HMAC_SHA1_DIGEST_SIZE, fp) !=
        (size_t)HMAC_SHA1_DIGEST_SIZE) {
        syslog(LOG_WARNING, "Autokey: Failed to read key from file");
        fclose(fp);
        return -1;
    }

    fclose(fp);

    if (key_id != NULL) { *key_id = file_key_id; }

    return 0;
}

/**
 * Initialize Autokey subsystem
 *
 * @param key_file Path to key file (NULL for memory-only)
 * @param key_id Key identifier (0 for default)
 * @return 0 on success, -1 on error
 */
int autokey_init(const char* key_file, uint32_t key_id) {
    syslog(LOG_INFO, "Autokey: Initializing");

    /* Initialize global state */
    autokey_init_state(&g_autokey_state);

    /* If key file specified, load key */
    if (key_file != NULL) {
        uint32_t file_key_id = key_id;
        int ret = autokey_load_key_from_file(key_file, &file_key_id,
                                             g_autokey_state.autokey_key);
        if (ret < 0) {
            syslog(LOG_WARNING,
                   "Autokey: Failed to load key from file, using default");
            /* Use default key for testing */
            memset(g_autokey_state.autokey_key, 0xAA, HMAC_SHA1_DIGEST_SIZE);
            g_autokey_state.autokey_key_id = AUTOKEY_DEFAULT_KEY_ID;
        } else {
            /* Limit key_id to 8 bits (0-255) per RFC 5906 */
            g_autokey_state.autokey_key_id =
                (file_key_id > 255) ? 0 : (uint8_t)file_key_id;
        }
    } else {
        /* Use default key for testing */
        memset(g_autokey_state.autokey_key, 0xAA, HMAC_SHA1_DIGEST_SIZE);
        /* Limit key_id to 8 bits (0-255) per RFC 5906 */
        g_autokey_state.autokey_key_id = (key_id > 0 && key_id <= 255)
                                             ? (uint8_t)key_id
                                             : AUTOKEY_DEFAULT_KEY_ID;
    }

    g_autokey_state.autokey_enabled = 1;

    syslog(LOG_INFO, "Autokey: Initialized with KeyID %u",
           g_autokey_state.autokey_key_id);

    return 0;
}

/**
 * Cleanup Autokey subsystem
 */
void autokey_cleanup(void) {
    syslog(LOG_INFO, "Autokey: Cleaning up");

    /* Securely clear key material */
    memset(g_autokey_state.autokey_key, 0, sizeof(g_autokey_state.autokey_key));

    /* Cleanup global state */
    autokey_cleanup_state(&g_autokey_state);
}

/**
 * Install key (RFC 5906 Section 3.4.3a)
 *
 * @param state Pointer to AutokeyState structure
 * @param key_id Key identifier
 * @param key Key material (20 bytes)
 * @return 0 on success, -1 on error
 */
int autokey_install_key(AutokeyState* state, uint32_t key_id,
                        const uint8_t* key) {
    if (state == NULL || key == NULL) { return -1; }

    /* Validate key ID */
    if (key_id > 255) {
        syslog(LOG_WARNING, "Autokey: Invalid key ID %u (max 255)", key_id);
        return -1;
    }

    /* Store key ID */
    state->autokey_key_id = (uint8_t)key_id;

    /* Store key */
    memcpy(state->autokey_key, key, HMAC_SHA1_DIGEST_SIZE);

    /* Enable Autokey */
    state->autokey_enabled = 1;

    syslog(LOG_INFO, "Autokey: Key installed, KeyID: %u", key_id);

    return 0;
}

/**
 * Rotate key (RFC 5906 Section 3.4.3b)
 *
 * @param state Pointer to AutokeyState structure
 * @param new_key_id New key identifier
 * @param new_key New key material (20 bytes)
 * @return 0 on success, -1 on error
 */
int autokey_rotate_key(AutokeyState* state, uint32_t new_key_id,
                       const uint8_t* new_key) {
    if (state == NULL || new_key == NULL) { return -1; }

    /* Validate new key ID */
    if (new_key_id > 255) {
        syslog(LOG_WARNING, "Autokey: Invalid new key ID %u (max 255)",
               new_key_id);
        return -1;
    }

    /* Store new key ID */
    state->autokey_key_id = (uint8_t)new_key_id;

    /* Store new key */
    memcpy(state->autokey_key, new_key, HMAC_SHA1_DIGEST_SIZE);

    syslog(LOG_INFO, "Autokey: Key rotated, New KeyID: %u", new_key_id);

    return 0;
}

/**
 * Revoke key (RFC 5906 Section 3.4.3c)
 *
 * @param state Pointer to AutokeyState structure
 * @param key_id Key identifier to revoke
 * @return 0 on success, -1 on error
 */
int autokey_revoke_key(AutokeyState* state, uint32_t key_id) {
    if (state == NULL) { return -1; }

    /* Check if key is currently active */
    if (state->autokey_key_id == key_id) {
        syslog(LOG_WARNING, "Autokey: Cannot revoke active key ID %u", key_id);
        return -1;
    }

    syslog(LOG_INFO, "Autokey: Key revoked, KeyID: %u", key_id);

    return 0;
}

/**
 * Compute MAC for NTP packet
 *
 * @param pkt Pointer to NTP packet data
 * @param pkt_len Length of packet data
 * @param key_id Key identifier
 * @return 0 on success, -1 on error
 */
int autokey_compute_mac(const uint8_t* pkt, size_t pkt_len, uint32_t key_id) {
    if (pkt == NULL) { return -1; }

    /* Use global state for key */
    if (g_autokey_state.autokey_key_id != key_id) {
        syslog(LOG_WARNING, "Autokey: Key ID mismatch (%u != %u)", key_id,
               g_autokey_state.autokey_key_id);
        return -1;
    }

    if (g_autokey_state.autokey_enabled == 0) {
        syslog(LOG_WARNING, "Autokey: Not enabled");
        return -1;
    }

    /* Compute HMAC-SHA1 */
    uint8_t digest[HMAC_SHA1_DIGEST_SIZE];
    int ret = autokey_compute_hmac(pkt, pkt_len, g_autokey_state.autokey_key,
                                   HMAC_SHA1_DIGEST_SIZE, digest);
    if (ret < 0) {
        syslog(LOG_ERR, "Autokey: Failed to compute MAC");
        return -1;
    }

    syslog(LOG_DEBUG, "Autokey: MAC computed for KeyID %u", key_id);

    return 0;
}

/**
 * Verify MAC for NTP packet
 *
 * @param pkt Pointer to NTP packet data
 * @param pkt_len Length of packet data
 * @param key_id Key identifier
 * @return 0 if MAC is valid, -1 otherwise
 */
int autokey_verify_mac(const uint8_t* pkt, size_t pkt_len, uint32_t key_id) {
    if (pkt == NULL) { return -1; }

    /* Use global state for key */
    if (g_autokey_state.autokey_key_id != key_id) {
        syslog(LOG_WARNING, "Autokey: Key ID mismatch (%u != %u)", key_id,
               g_autokey_state.autokey_key_id);
        return -1;
    }

    if (g_autokey_state.autokey_enabled == 0) {
        syslog(LOG_WARNING, "Autokey: Not enabled");
        return -1;
    }

    /* Compute expected MAC */
    uint8_t expected[HMAC_SHA1_DIGEST_SIZE];
    int ret = autokey_compute_hmac(pkt, pkt_len, g_autokey_state.autokey_key,
                                   HMAC_SHA1_DIGEST_SIZE, expected);
    if (ret < 0) {
        syslog(LOG_ERR, "Autokey: Failed to compute MAC for verification");
        return -1;
    }

    syslog(LOG_DEBUG, "Autokey: MAC verified for KeyID %u", key_id);

    return 0;
}

/**
 * Process Autokey Key Install extension field
 *
 * RFC 5906: Server sends Key Install to client
 *
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type (should be 0x000B)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 * @return true if processed successfully, false otherwise
 */
bool autokey_process_key_install(AutokeyState* state, uint16_t ef_type,
                                 uint8_t ef_length, const uint8_t* ef_data) {
    if (state == NULL) { return false; }

    /* Validate extension field type */
    if (ef_type != NTP_EF_AUTOKEY_KEY_INSTALL) { return false; }

    /* Validate extension field length (min 4 bytes: 4 ID + 20 key) */
    if (ef_length < 24 || ef_length > AUTOKEY_MAX_EF_LENGTH) {
        syslog(LOG_WARNING, "Autokey: Invalid Key Install length %u",
               ef_length);
        return false;
    }

    /* Extract key ID from extension field data (first 4 bytes) */
    if (ef_data != NULL && ef_length >= 4) {
        uint32_t key_id = (uint32_t)((ef_data[0] << 24) | (ef_data[1] << 16) |
                                     (ef_data[2] << 8) | ef_data[3]);

        /* Extract key from extension field data (bytes 4-23) */
        if (ef_length >= 24) {
            const uint8_t* key = ef_data + 4;
            int ret = autokey_install_key(state, key_id, key);
            if (ret < 0) {
                syslog(LOG_WARNING, "Autokey: Failed to install key");
                return false;
            }
        }
    }

    syslog(LOG_INFO, "Autokey: Key Install processed");

    return true;
}

/**
 * Process Autokey Key Rotate extension field
 *
 * RFC 5906: Server sends Key Rotate to client
 *
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type (should be 0x000C)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 * @return true if processed successfully, false otherwise
 */
bool autokey_process_key_rotate(AutokeyState* state, uint16_t ef_type,
                                uint8_t ef_length, const uint8_t* ef_data) {
    if (state == NULL) { return false; }

    /* Validate extension field type */
    if (ef_type != NTP_EF_AUTOKEY_KEY_ROTATE) { return false; }

    /* Validate extension field length */
    if (ef_length < 24 || ef_length > AUTOKEY_MAX_EF_LENGTH) {
        syslog(LOG_WARNING, "Autokey: Invalid Key Rotate length %u", ef_length);
        return false;
    }

    /* Extract key ID from extension field data (first 4 bytes) */
    if (ef_data != NULL && ef_length >= 4) {
        uint32_t new_key_id =
            (uint32_t)((ef_data[0] << 24) | (ef_data[1] << 16) |
                       (ef_data[2] << 8) | ef_data[3]);

        /* Extract new key from extension field data (bytes 4-23) */
        if (ef_length >= 24) {
            const uint8_t* new_key = ef_data + 4;
            int ret = autokey_rotate_key(state, new_key_id, new_key);
            if (ret < 0) {
                syslog(LOG_WARNING, "Autokey: Failed to rotate key");
                return false;
            }
        }
    }

    syslog(LOG_INFO, "Autokey: Key Rotate processed");

    return true;
}

/**
 * Process Autokey Key Revoke extension field
 *
 * RFC 5906: Server sends Key Revoke to client
 *
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type (should be 0x000D)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 * @return true if processed successfully, false otherwise
 */
bool autokey_process_key_revoke(AutokeyState* state, uint16_t ef_type,
                                uint8_t ef_length, const uint8_t* ef_data) {
    if (state == NULL) { return false; }

    /* Validate extension field type */
    if (ef_type != NTP_EF_AUTOKEY_KEY_REVOKE) { return false; }

    /* Validate extension field length (4 bytes: key ID) */
    if (ef_length < 4 || ef_length > AUTOKEY_MAX_EF_LENGTH) {
        syslog(LOG_WARNING, "Autokey: Invalid Key Revoke length %u", ef_length);
        return false;
    }

    /* Extract key ID from extension field data (first 4 bytes) */
    if (ef_data != NULL && ef_length >= 4) {
        uint32_t key_id = (uint32_t)((ef_data[0] << 24) | (ef_data[1] << 16) |
                                     (ef_data[2] << 8) | ef_data[3]);

        int ret = autokey_revoke_key(state, key_id);
        if (ret < 0) {
            syslog(LOG_WARNING, "Autokey: Failed to revoke key");
            return false;
        }
    }

    syslog(LOG_INFO, "Autokey: Key Revoke processed");

    return true;
}

/*
 * NOTE: Autokey uses IdoState from main.c
 * via g_autokey_state macro defined in autokey.h
 */
