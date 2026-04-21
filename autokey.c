/*
 * autokey.c - Autokey Security Protocol Implementation (RFC 5906)
 *
 * Simplified Autokey implementation with:
 * - Autokey Offer/Response extension fields parsing
 * - State machine implementation
 * - Capability flags handling
 * - State transitions
 * - Memory safety
 * - Error handling
 *
 * Note: HMAC-SHA1 MAC computation is not implemented yet.
 * This can be added later using libgcrypt or OpenSSL.
 */

#include "autokey.h"
#include "ido.h"
#include "ntp_packet.h"
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
bool autokey_process_offer(AutokeyState* state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data) {
    if (state == NULL) { return false; }

    /* Validate extension field type */
    if (ef_type != NTP_EF_AUTOKEY_OFFER) { return false; }

    /* Validate extension field length (min 4 bytes) */
    if (ef_length < AUTOKEY_MIN_EF_LENGTH || ef_length > AUTOKEY_MAX_EF_LENGTH) {
        syslog(LOG_WARNING, "Autokey: Invalid offer length %u", ef_length);
        return false;
    }

    /* Extract capability flags from extension field data */
    if (ef_data != NULL && ef_length >= 4) {
        /* Capability flags are in the first byte */
        uint8_t flags = ef_data[0];
        if (ef_length > 0) { state->autokey_capabilities = flags & 0x07; /* Only lower 3 bits */ }
    }

    /* Transition state machine */
    state->autokey_offer_received = 1;
    state->autokey_state = AUTOKEY_STATE_OFFER_RECEIVED;

    /* Log state transition */
    syslog(LOG_INFO, "Autokey: Offer received, state: %s", autokey_state_name(state->autokey_state));

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
bool autokey_process_response(AutokeyState* state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data) {
    if (state == NULL) { return false; }

    /* Validate extension field type */
    if (ef_type != NTP_EF_AUTOKEY_RESPONSE) { return false; }

    /* Validate extension field length (min 4 bytes) */
    if (ef_length < AUTOKEY_MIN_EF_LENGTH || ef_length > AUTOKEY_MAX_EF_LENGTH) {
        syslog(LOG_WARNING, "Autokey: Invalid response length %u", ef_length);
        return false;
    }

    /* Extract capability flags from extension field data */
    if (ef_data != NULL && ef_length >= 4) {
        /* Capability flags are in the first byte */
        uint8_t flags = ef_data[0];
        if (ef_length > 0) { state->autokey_capabilities = flags & 0x07; /* Only lower 3 bits */ }
    }

    /* Transition state machine */
    state->autokey_response_sent = 1;
    state->autokey_state = AUTOKEY_STATE_AUTHENTICATED;
    state->autokey_authenticated = 1;

    /* Log state transition */
    syslog(LOG_INFO, "Autokey: Response sent, state: %s", autokey_state_name(state->autokey_state));

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
bool autokey_process(AutokeyState* state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data) {
    if (state == NULL || ef_data == NULL) { return false; }

    /* Check if it's an Offer (server -> client) */
    if (ef_type == NTP_EF_AUTOKEY_OFFER) { return autokey_process_offer(state, ef_type, ef_length, ef_data); }

    /* Check if it's a Response (client -> server) */
    if (ef_type == NTP_EF_AUTOKEY_RESPONSE) { return autokey_process_response(state, ef_type, ef_length, ef_data); }

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
bool autokey_process_skip(AutokeyState* state, uint16_t ef_type, uint8_t ef_length) {
    /* Validate extension field type */
    if (ef_type != NTP_EF_AUTOKEY_OFFER && ef_type != NTP_EF_AUTOKEY_RESPONSE) { return false; }

    /* Validate extension field length (min 4 bytes) */
    if (ef_length < AUTOKEY_MIN_EF_LENGTH || ef_length > AUTOKEY_MAX_EF_LENGTH) {
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
 *   │                            │                             ├─ Key installation
 *   │                            │                             │
 *   │                            │                             └─ Authentication
 * ──→ REJECTED
 *   │
 *   └─ Autokey Response sent ──→ RESPONSE_SENT
 *                                │
 *                                └─ No offer received ──→ REJECTED
 */
uint8_t autokey_state_machine(AutokeyState* state, uint8_t event) {
    if (state == NULL) { return AUTOKEY_STATE_IDLE; }

    uint8_t new_state = state->autokey_state;

    switch (event) {
    case AUTOKEY_EVENT_OFFER_RECEIVED:
        /* IDLE → OFFER_RECEIVED */
        if (state->autokey_state == AUTOKEY_STATE_IDLE) { new_state = AUTOKEY_STATE_OFFER_RECEIVED; }
        break;

    case AUTOKEY_EVENT_RESPONSE_SENT:
        /* OFFER_RECEIVED → RESPONSE_SENT */
        if (state->autokey_state == AUTOKEY_STATE_OFFER_RECEIVED) { new_state = AUTOKEY_STATE_RESPONSE_SENT; }
        break;

    case AUTOKEY_EVENT_AUTH_ESTABLISHED:
        /* RESPONSE_SENT → AUTHENTICATED */
        if (state->autokey_state == AUTOKEY_STATE_RESPONSE_SENT) { new_state = AUTOKEY_STATE_AUTHENTICATED; }
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
        syslog(LOG_INFO, "Autokey: State transition: %s → %s", autokey_state_name(prev_state), autokey_state_name(new_state));
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
           autokey_state_name(state->autokey_state), state->autokey_offer_received ? "yes" : "no", state->autokey_response_sent ? "yes" : "no",
           state->autokey_capabilities, state->autokey_key_id, state->autokey_authenticated ? "yes" : "no");
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
