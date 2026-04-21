/*
 * ido.h - I-DO/Autokey Capability Negotiation Header
 *
 * RFC 5905 Section 8.4: Message Authentication Code (MAC) Extension
 * RFC 5906: Autokey Security Protocol
 *
 * I-DO (I-DO Offer/Response) Capability Negotiation
 * Autokey (Autokey Offer/Response/Key Management)
 *
 * This header defines the state machine and functions for
 * negotiating message authentication capabilities between NTP peers.
 *
 * States:
 *   - IDLE: Initial state, no negotiation
 *   - OFFER_RECEIVED: Offer received from peer
 *   - RESPONSE_SENT: Response sent to peer
 *   - AUTHENTICATED: Authentication established
 *   - REJECTED: Negotiation failed
 *
 * Capability Flags:
 *   - IDO_CAP_OFFER (0x01): Peer offers authentication
 *   - IDO_CAP_RESPONSE (0x02): Client responds to offer
 *   - IDO_CAP_RESERVED (0x04): Reserved for future use
 *
 * Extension Field Types:
 *   - I-DO Offer: type=0x0007
 *   - I-DO Response: type=0x8007
 *   - Autokey Offer: type=0x000A
 *   - Autokey Response: type=0x800A
 */

#ifndef IDO_H
#define IDO_H

#include <stdbool.h>
#include <stdint.h>

/* I-DO/Autokey State Machine States */
typedef enum {
    IDO_STATE_IDLE = 0,
    IDO_STATE_OFFER_RECEIVED,
    IDO_STATE_RESPONSE_SENT,
    IDO_STATE_AUTHENTICATED,
    IDO_STATE_REJECTED
} IdoState_t;

/* I-DO/Autokey Capability Flags */
#define IDO_CAP_OFFER (0x01)    /* Peer offers authentication */
#define IDO_CAP_RESPONSE (0x02) /* Client responds to offer */
#define IDO_CAP_RESERVED (0x04) /* Reserved for future use */

/* I-DO Extension Field Types */
#define IDO_EF_TYPE_OFFER (0x0007)    /* I-DO Offer */
#define IDO_EF_TYPE_RESPONSE (0x8007) /* I-DO Response */

/* Autokey Extension Field Types */
#define IDO_EF_AUTOKEY_OFFER (0x000A)       /* Autokey Offer */
#define IDO_EF_AUTOKEY_RESPONSE (0x800A)    /* Autokey Response */
#define IDO_EF_AUTOKEY_KEY_INSTALL (0x000B) /* Key Install */
#define IDO_EF_AUTOKEY_KEY_ROTATE (0x000C)  /* Key Rotate */
#define IDO_EF_AUTOKEY_KEY_REVOKE (0x000D)  /* Key Revoke */

/* I-DO/Autokey State Structure */
typedef struct {
    uint8_t ido_state;          /* Current state machine state */
    uint8_t ido_offer_received; /* Offer received from peer */
    uint8_t ido_response_sent;  /* Response sent to peer */
    uint8_t ido_capabilities;   /* Capability flags */
    uint8_t ido_key_id;         /* Key identifier (Autokey) */
    uint8_t ido_key[20];        /* HMAC-SHA1 key (20 bytes) */
    uint8_t ido_enabled;        /* Authentication enabled flag */
    uint8_t ido_authenticated;  /* Authentication established */
} IdoState;

/* I-DO State Machine Functions */

/**
 * Initialize I-DO state machine
 * @param ido_state Pointer to IdoState structure
 *
 * Resets all I-DO state to initial values:
 * - State: IDLE
 * - Offer received: false
 * - Response sent: false
 * - Capabilities: 0
 * - Key ID: 0
 * - Key: all zeros
 * - Enabled: false
 * - Authenticated: false
 */
void ido_state_init(IdoState* ido_state);

/**
 * Cleanup I-DO state machine
 * @param ido_state Pointer to IdoState structure
 *
 * Cleans up I-DO state (optional, for resource management)
 */
void ido_state_cleanup(IdoState* ido_state);

/**
 * Process I-DO Offer extension field
 * @param ido_state Pointer to IdoState structure
 * @param ef_type Extension field type (should be 0x0007)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 *
 * Handles I-DO Offer from server:
 * - Validates extension field type
 * - Validates extension field length (min 4 bytes)
 * - Extracts capability flags
 * - Transitions state to OFFER_RECEIVED
 * - Logs state transition
 *
 * Returns true if offer processed successfully, false otherwise
 */
bool ido_process_offer(IdoState* ido_state, uint16_t ef_type, uint8_t ef_length,
                       const uint8_t* ef_data);

/**
 * Process I-DO Response extension field
 * @param ido_state Pointer to IdoState structure
 * @param ef_type Extension field type (should be 0x8007)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 *
 * Handles I-DO Response to server:
 * - Validates extension field type
 * - Validates extension field length (min 4 bytes)
 * - Extracts capability flags
 * - Transitions state to AUTHENTICATED or REJECTED
 * - Logs state transition
 *
 * Returns true if response processed successfully, false otherwise
 */
bool ido_process_response(IdoState* ido_state, uint16_t ef_type,
                          uint8_t ef_length, const uint8_t* ef_data);

/**
 * Process I-DO extension field (unified interface)
 * @param ido_state Pointer to IdoState structure
 * @param ef_type Extension field type
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 *
 * Unified interface for processing I-DO extension fields:
 * - type=0x0007: I-DO Offer (server -> client)
 * - type=0x8007: I-DO Response (client -> server)
 *
 * Returns true if extension field processed successfully, false otherwise
 */
bool ido_process(IdoState* ido_state, uint16_t ef_type, uint8_t ef_length,
                 const uint8_t* ef_data);

/**
 * Process I-DO extension field (skip mode for parsing)
 * @param ido_state Pointer to IdoState structure
 * @param ef_type Extension field type
 * @param ef_length Extension field length
 *
 * Skip mode for extension field parsing:
 * - Validates extension field type
 * - Validates extension field length
 * - Updates state machine without processing data
 * - Used in skip_extension_fields()
 *
 * Returns true if extension field is valid I-DO, false otherwise
 */
bool ido_process_skip(IdoState* ido_state, uint16_t ef_type, uint8_t ef_length);

/**
 * State machine transition handler
 * @param ido_state Pointer to IdoState structure
 * @param event Event type (OFFER_RECEIVED, RESPONSE_SENT, etc.)
 *
 * Handles state machine transitions based on events:
 * - IDLE → OFFER_RECEIVED: I-DO Offer received
 * - OFFER_RECEIVED → RESPONSE_SENT: Send I-DO Response
 * - RESPONSE_SENT → AUTHENTICATED: Authentication established
 * - Any state → REJECTED: I-DO negotiation failed
 *
 * Returns new state after transition
 */
uint8_t ido_state_machine(IdoState* ido_state, uint8_t event);

/**
 * Check if I-DO is authenticated
 * @param ido_state Pointer to IdoState structure
 *
 * Returns true if I-DO authentication is established, false otherwise
 */
bool ido_is_authenticated(const IdoState* ido_state);

/**
 * Log I-DO state
 * @param ido_state Pointer to IdoState structure
 *
 * Logs current I-DO state for debugging
 */
void ido_log_state(const IdoState* ido_state);

/**
 * Get I-DO state name
 * @param state State value
 *
 * Returns human-readable state name
 */
const char* ido_state_name(uint8_t state);

/**
 * Get I-DO capability flag name
 * @param flag Flag value
 *
 * Returns human-readable flag name
 */
const char* ido_capability_name(uint8_t flag);

/* Global I-DO state */
extern IdoState g_ido_state;

#endif /* IDO_H */
