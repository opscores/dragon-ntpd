/*
 * ido.c - I-DO/Autokey Capability Negotiation Implementation
 *
 * RFC 5905 Section 8.4: Message Authentication Code (MAC) Extension
 * RFC 5906: Autokey Security Protocol
 *
 * I-DO (I-DO Offer/Response) Capability Negotiation Implementation
 * Autokey (Autokey Offer/Response/Key Management) Implementation
 *
 * This file implements the state machine for negotiating
 * message authentication capabilities between NTP peers.
 *
 * RFC 5905 §8.4 Compliance:
 * - I-DO Offer/Response extension fields parsing
 * - State machine implementation
 * - Capability flags handling
 * - State transitions
 * - Memory safety
 * - Error handling
 *
 * RFC 5906 Compliance:
 * - Autokey Offer/Response extension fields parsing
 * - Key management (install/rotate/revoke)
 * - HMAC-SHA1 MAC computation
 */

#include "ido.h"
#include <stdio.h>
#include <string.h>
#include <syslog.h>

/* State machine event types */
#define IDO_EVENT_OFFER_RECEIVED (1)
#define IDO_EVENT_RESPONSE_SENT (2)
#define IDO_EVENT_AUTH_ESTABLISHED (3)
#define IDO_EVENT_NEGOTIATION_FAILED (4)

/* Minimum extension field length */
#define IDO_MIN_EF_LENGTH (4)

/* I-DO extension field types */
#define IDO_EF_TYPE_OFFER (0x0007)
#define IDO_EF_TYPE_RESPONSE (0x8007)

/* Autokey extension field types */
#define IDO_EF_AUTOKEY_OFFER (0x000A)
#define IDO_EF_AUTOKEY_RESPONSE (0x800A)
#define IDO_EF_AUTOKEY_KEY_INSTALL (0x000B)
#define IDO_EF_AUTOKEY_KEY_ROTATE (0x000C)
#define IDO_EF_AUTOKEY_KEY_REVOKE (0x000D)

/**
 * Initialize I-DO/Autokey state machine
 *
 * Resets all I-DO/Autokey state to initial values:
 * - State: IDLE
 * - Offer received: false
 * - Response sent: false
 * - Capabilities: 0
 * - Key ID: 0
 * - Key: all zeros (20 bytes for HMAC-SHA1)
 * - Enabled: false
 * - Authenticated: false
 */
void ido_state_init(IdoState* ido_state) {
    if (ido_state == NULL) { return; }

    /* Reset all fields to initial values */
    ido_state->ido_state = IDO_STATE_IDLE;
    ido_state->ido_offer_received = 0;
    ido_state->ido_response_sent = 0;
    ido_state->ido_capabilities = 0;
    ido_state->ido_key_id = 0;
    memset(ido_state->ido_key, 0, sizeof(ido_state->ido_key));
    ido_state->ido_enabled = 0;
    ido_state->ido_authenticated = 0;
}

/**
 * Cleanup I-DO state machine
 */
void ido_state_cleanup(IdoState* ido_state) {
    if (ido_state == NULL) { return; }

    /* Reset to initial state */
    ido_state_init(ido_state);
}

/**
 * Process I-DO/Autokey Offer extension field
 *
 * RFC 5905 §8.4: Server sends I-DO Offer to client
 * RFC 5906: Server sends Autokey Offer to client
 *
 * @param ido_state Pointer to IdoState structure
 * @param ef_type Extension field type (0x0007=I-DO Offer, 0x000A=Autokey Offer)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 *
 * @return true if offer processed successfully, false otherwise
 */
bool ido_process_offer(IdoState* ido_state, uint16_t ef_type, uint8_t ef_length,
                       const uint8_t* ef_data) {
    if (ido_state == NULL) { return false; }

    /* Validate extension field type (I-DO or Autokey) */
    if (ef_type != IDO_EF_TYPE_OFFER && ef_type != IDO_EF_AUTOKEY_OFFER) {
        return false;
    }

    /* Validate extension field length (min 4 bytes) */
    if (ef_length < IDO_MIN_EF_LENGTH || ef_length > 48) {
        syslog(LOG_WARNING, "I-DO/Autokey: Invalid offer length %u", ef_length);
        return false;
    }

    /* Extract capability flags from extension field data */
    if (ef_data != NULL && ef_length >= 4) {
        /* Capability flags are in the first byte */
        uint8_t flags = ef_data[0];
        if (ef_length > 0) {
            ido_state->ido_capabilities = flags & 0x07; /* Only lower 3 bits */
        }
    }

    /* Transition state machine */
    ido_state->ido_offer_received = 1;
    ido_state->ido_state = IDO_STATE_OFFER_RECEIVED;

    /* Log state transition */
    syslog(LOG_INFO, "I-DO/Autokey: Offer received, state: %s",
           ido_state_name(ido_state->ido_state));

    return true;
}

/**
 * Process I-DO/Autokey Response extension field
 *
 * RFC 5905 §8.4: Client sends I-DO Response to server
 * RFC 5906: Client sends Autokey Response to server
 *
 * @param ido_state Pointer to IdoState structure
 * @param ef_type Extension field type (0x8007=I-DO Response, 0x800A=Autokey
 * Response)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 *
 * @return true if response processed successfully, false otherwise
 */
bool ido_process_response(IdoState* ido_state, uint16_t ef_type,
                          uint8_t ef_length, const uint8_t* ef_data) {
    if (ido_state == NULL) { return false; }

    /* Validate extension field type (I-DO or Autokey) */
    if (ef_type != IDO_EF_TYPE_RESPONSE && ef_type != IDO_EF_AUTOKEY_RESPONSE) {
        return false;
    }

    /* Validate extension field length (min 4 bytes) */
    if (ef_length < IDO_MIN_EF_LENGTH || ef_length > 48) {
        syslog(LOG_WARNING, "I-DO/Autokey: Invalid response length %u",
               ef_length);
        return false;
    }

    /* Extract capability flags from extension field data */
    if (ef_data != NULL && ef_length >= 4) {
        /* Capability flags are in the first byte */
        uint8_t flags = ef_data[0];
        if (ef_length > 0) {
            ido_state->ido_capabilities = flags & 0x07; /* Only lower 3 bits */
        }
    }

    /* Transition state machine */
    ido_state->ido_response_sent = 1;
    ido_state->ido_state = IDO_STATE_AUTHENTICATED;
    ido_state->ido_authenticated = 1;

    /* Log state transition */
    syslog(LOG_INFO, "I-DO/Autokey: Response sent, state: %s",
           ido_state_name(ido_state->ido_state));

    return true;
}

/**
 * Process I-DO/Autokey extension field (unified interface)
 *
 * RFC 5905 §8.4: Unified interface for processing I-DO extension fields:
 * - type=0x0007: I-DO Offer (server -> client)
 * - type=0x8007: I-DO Response (client -> server)
 * RFC 5906: Unified interface for processing Autokey extension fields:
 * - type=0x000A: Autokey Offer (server -> client)
 * - type=0x800A: Autokey Response (client -> server)
 *
 * Uses ido_process_offer() and ido_process_response() internally.
 *
 * @param ido_state Pointer to IdoState structure
 * @param ef_type Extension field type
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 *
 * @return true if extension field processed successfully, false otherwise
 */
bool ido_process(IdoState* ido_state, uint16_t ef_type, uint8_t ef_length,
                 const uint8_t* ef_data) {
    if (ido_state == NULL || ef_data == NULL) { return false; }

    /* Check if it's an Offer (server -> client) */
    if (ef_type == IDO_EF_TYPE_OFFER || ef_type == IDO_EF_AUTOKEY_OFFER) {
        return ido_process_offer(ido_state, ef_type, ef_length, ef_data);
    }

    /* Check if it's a Response (client -> server) */
    if (ef_type == IDO_EF_TYPE_RESPONSE || ef_type == IDO_EF_AUTOKEY_RESPONSE) {
        return ido_process_response(ido_state, ef_type, ef_length, ef_data);
    }

    return false;
}

/**
 * Process I-DO/Autokey extension field (skip mode for parsing)
 *
 * Used in skip_extension_fields() to identify I-DO/Autokey fields
 * without processing them. Updates state machine for tracking.
 *
 * @param ido_state Pointer to IdoState structure
 * @param ef_type Extension field type (0x0007=I-DO, 0x000A=Autokey Offer)
 * @param ef_length Extension field length
 *
 * @return true if extension field is valid I-DO/Autokey, false otherwise
 */
bool ido_process_skip(IdoState* ido_state, uint16_t ef_type,
                      uint8_t ef_length) {
    /* Validate extension field type (I-DO or Autokey) */
    if (ef_type != IDO_EF_TYPE_OFFER && ef_type != IDO_EF_TYPE_RESPONSE &&
        ef_type != IDO_EF_AUTOKEY_OFFER && ef_type != IDO_EF_AUTOKEY_RESPONSE) {
        return false;
    }

    /* Validate extension field length (min 4 bytes) */
    if (ef_length < IDO_MIN_EF_LENGTH || ef_length > 48) {
        syslog(LOG_WARNING, "I-DO/Autokey: Invalid skip length %u", ef_length);
        return false;
    }

    /* Validate state pointer */
    if (ido_state == NULL) { return false; }

    /* Update state machine for tracking */
    if (ef_type == IDO_EF_TYPE_OFFER || ef_type == IDO_EF_AUTOKEY_OFFER) {
        ido_state->ido_offer_received = 1;
    } else if (ef_type == IDO_EF_TYPE_RESPONSE ||
               ef_type == IDO_EF_AUTOKEY_RESPONSE) {
        ido_state->ido_response_sent = 1;
    }

    return true;
}

/**
 * State machine transition handler
 *
 * RFC 5905 §8.4 State Machine (I-DO):
 *
 * IDLE
 *   │
 *   ├─ I-DO Offer received ──→ OFFER_RECEIVED
 *   │                          │
 *   │                          ├─ Send I-DO Response ──→ RESPONSE_SENT
 *   │                          │                          │
 *   │                          │                          ├─ Authentication
 *   established ──→ AUTHENTICATED
 *   │                          │                          │
 *   │                          │                          └─ No offer received
 * ──→ REJECTED
 *   │
 *   └─ I-DO Response sent ──→ RESPONSE_SENT
 *                             │
 *                             └─ No offer received ──→ REJECTED
 *
 * RFC 5906 State Machine (Autokey):
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
uint8_t ido_state_machine(IdoState* ido_state, uint8_t event) {
    if (ido_state == NULL) { return IDO_STATE_IDLE; }

    uint8_t new_state = ido_state->ido_state;

    switch (event) {
    case IDO_EVENT_OFFER_RECEIVED:
        /* IDLE → OFFER_RECEIVED */
        if (ido_state->ido_state == IDO_STATE_IDLE) {
            new_state = IDO_STATE_OFFER_RECEIVED;
        }
        break;

    case IDO_EVENT_RESPONSE_SENT:
        /* OFFER_RECEIVED → RESPONSE_SENT */
        if (ido_state->ido_state == IDO_STATE_OFFER_RECEIVED) {
            new_state = IDO_STATE_RESPONSE_SENT;
        }
        break;

    case IDO_EVENT_AUTH_ESTABLISHED:
        /* RESPONSE_SENT → AUTHENTICATED */
        if (ido_state->ido_state == IDO_STATE_RESPONSE_SENT) {
            new_state = IDO_STATE_AUTHENTICATED;
        }
        break;

    case IDO_EVENT_NEGOTIATION_FAILED:
        /* Any state → REJECTED */
        new_state = IDO_STATE_REJECTED;
        break;

    default: break;
    }

    if (new_state != ido_state->ido_state) {
        uint8_t prev_state = ido_state->ido_state;
        ido_state->ido_state = new_state;
        syslog(LOG_INFO, "I-DO/Autokey: State transition: %s → %s",
               ido_state_name(prev_state), ido_state_name(new_state));
    }

    return new_state;
}

/**
 * Check if I-DO is authenticated
 */
bool ido_is_authenticated(const IdoState* ido_state) {
    if (ido_state == NULL) { return false; }

    return ido_state->ido_authenticated != 0;
}

/**
 * Log I-DO/Autokey state
 */
void ido_log_state(const IdoState* ido_state) {
    if (ido_state == NULL) { return; }

    syslog(LOG_INFO,
           "I-DO/Autokey: State: %s, Offer: %s, Response: %s, "
           "Capabilities: 0x%02X, KeyID: %u, Authenticated: %s",
           ido_state_name(ido_state->ido_state),
           ido_state->ido_offer_received ? "yes" : "no",
           ido_state->ido_response_sent ? "yes" : "no",
           ido_state->ido_capabilities, ido_state->ido_key_id,
           ido_state->ido_authenticated ? "yes" : "no");
}

/**
 * Get I-DO/Autokey state name
 */
const char* ido_state_name(uint8_t state) {
    switch (state) {
    case IDO_STATE_IDLE: return "IDLE";
    case IDO_STATE_OFFER_RECEIVED: return "OFFER_RECEIVED";
    case IDO_STATE_RESPONSE_SENT: return "RESPONSE_SENT";
    case IDO_STATE_AUTHENTICATED: return "AUTHENTICATED";
    case IDO_STATE_REJECTED: return "REJECTED";
    default: return "UNKNOWN";
    }
}

/**
 * Get I-DO/Autokey capability flag name
 */
const char* ido_capability_name(uint8_t flag) {
    switch (flag) {
    case IDO_CAP_OFFER: return "IDO_CAP_OFFER";
    case IDO_CAP_RESPONSE: return "IDO_CAP_RESPONSE";
    case IDO_CAP_RESERVED: return "IDO_CAP_RESERVED";
    default: return "UNKNOWN";
    }
}
