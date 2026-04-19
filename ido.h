/*
 * ido.h - I-DO Capability Negotiation Header
 *
 * RFC 5905 Section 8.4: Message Authentication Code (MAC) Extension
 *
 * I-DO (I-DO Offer/Response) Capability Negotiation
 *
 * This header defines the I-DO state machine and functions for
 * negotiating message authentication capabilities between NTP peers.
 *
 * States:
 *   - IDLE: Initial state, no I-DO negotiation
 *   - OFFER_RECEIVED: I-DO Offer received from server
 *   - RESPONSE_SENT: I-DO Response sent to server
 *   - AUTHENTICATED: Authentication established
 *   - REJECTED: I-DO negotiation failed
 *
 * Capability Flags:
 *   - IDO_CAP_OFFER (0x01): Server offers authentication
 *   - IDO_CAP_RESPONSE (0x02): Client responds to offer
 *   - IDO_CAP_RESERVED (0x04): Reserved for future use
 *
 * Extension Field Types:
 *   - I-DO Offer: type=0x0007
 *   - I-DO Response: type=0x8007
 */

#ifndef IDO_H
#define IDO_H

#include <stdbool.h>
#include <stdint.h>

/* I-DO State Machine States */
typedef enum { IDO_STATE_IDLE = 0, IDO_STATE_OFFER_RECEIVED, IDO_STATE_RESPONSE_SENT, IDO_STATE_AUTHENTICATED, IDO_STATE_REJECTED } IdoState_t;

/* I-DO Capability Flags */
#define IDO_CAP_OFFER (0x01)    /* Server offers authentication */
#define IDO_CAP_RESPONSE (0x02) /* Client responds to offer */
#define IDO_CAP_RESERVED (0x04) /* Reserved for future use */

/* I-DO Extension Field Types */
#define IDO_EF_TYPE_OFFER (0x0007)    /* I-DO Offer */
#define IDO_EF_TYPE_RESPONSE (0x8007) /* I-DO Response */

/* I-DO State Structure */
typedef struct {
    uint8_t ido_state;          /* Current state machine state */
    uint8_t ido_offer_received; /* I-DO Offer received from server */
    uint8_t ido_response_sent;  /* I-DO Response sent to server */
    uint8_t ido_capabilities;   /* Capability flags */
    uint8_t ido_key_id;         /* Key identifier (for future) */
    uint8_t ido_key[16];        /* MAC key (for future, 128-bit) */
    uint8_t ido_enabled;        /* I-DO enabled flag */
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
bool ido_process_offer(IdoState* ido_state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data);

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
bool ido_process_response(IdoState* ido_state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data);

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
bool ido_process(IdoState* ido_state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data);

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

#endif /* IDO_H */
