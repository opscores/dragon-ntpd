/*
 * autokey.h - Autokey Security Protocol Header (RFC 5906)
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

#ifndef AUTOKEY_H
#define AUTOKEY_H

#include "ntpd.h"
#include <stdbool.h>
#include <stdint.h>

/* ============================================================================
 * Autokey State Machine States
 * ============================================================================
 */

typedef enum {
    AUTOKEY_STATE_IDLE = 0,
    AUTOKEY_STATE_OFFER_RECEIVED,
    AUTOKEY_STATE_RESPONSE_SENT,
    AUTOKEY_STATE_AUTHENTICATED,
    AUTOKEY_STATE_REJECTED
} AutokeyState_t;

/* ============================================================================
 * Autokey Capability Flags
 * ============================================================================
 */

#define AUTOKEY_CAP_OFFER (0x01)    /* Peer offers authentication */
#define AUTOKEY_CAP_RESPONSE (0x02) /* Client responds to offer */
#define AUTOKEY_CAP_RESERVED (0x04) /* Reserved for future use */

/* ============================================================================
 * Autokey State Structure
 * ============================================================================
 */

typedef struct {
    uint8_t autokey_state;          /* Current state machine state */
    uint8_t autokey_offer_received; /* Autokey Offer received from peer */
    uint8_t autokey_response_sent;  /* Autokey Response sent to peer */
    uint8_t autokey_capabilities;   /* Capability flags */
    uint8_t autokey_key_id;         /* Key identifier (Autokey) */
    uint8_t autokey_key[20];        /* HMAC-SHA1 key (20 bytes) */
    uint8_t autokey_enabled;        /* Autokey enabled flag */
    uint8_t autokey_authenticated;  /* Authentication established */
} AutokeyState;

/* ============================================================================
 * Autokey State Machine Functions
 * ============================================================================
 */

/**
 * Initialize Autokey state machine
 * @param state Pointer to AutokeyState structure
 */
void autokey_init_state(AutokeyState* state);

/**
 * Cleanup Autokey state machine
 * @param state Pointer to AutokeyState structure
 */
void autokey_cleanup_state(AutokeyState* state);

/**
 * Process Autokey Offer extension field
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type (should be 0x000A)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 * @return true if offer processed successfully, false otherwise
 */
bool autokey_process_offer(AutokeyState* state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data);

/**
 * Process Autokey Response extension field
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type (should be 0x800A)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 * @return true if response processed successfully, false otherwise
 */
bool autokey_process_response(AutokeyState* state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data);

/**
 * Process Autokey extension field (unified interface)
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 * @return true if extension field processed successfully, false otherwise
 */
bool autokey_process(AutokeyState* state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data);

/**
 * Process Autokey extension field (skip mode for parsing)
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type
 * @param ef_length Extension field length
 * @return true if extension field is valid Autokey, false otherwise
 */
bool autokey_process_skip(AutokeyState* state, uint16_t ef_type, uint8_t ef_length);

/**
 * State machine transition handler
 * @param state Pointer to AutokeyState structure
 * @param event Event type (OFFER_RECEIVED, RESPONSE_SENT, etc.)
 * @return new state after transition
 */
uint8_t autokey_state_machine(AutokeyState* state, uint8_t event);

/**
 * Check if Autokey is authenticated
 * @param state Pointer to AutokeyState structure
 * @return true if Autokey authentication is established, false otherwise
 */
bool autokey_is_authenticated(const AutokeyState* state);

/**
 * Log Autokey state
 * @param state Pointer to AutokeyState structure
 */
void autokey_log_state(const AutokeyState* state);

/**
 * Get Autokey state name
 * @param state State value
 * @return human-readable state name
 */
const char* autokey_state_name(uint8_t state);

/**
 * Get Autokey capability flag name
 * @param flag Flag value
 * @return human-readable flag name
 */
const char* autokey_capability_name(uint8_t flag);

/* ============================================================================
 * Global Variables
 * ============================================================================
 */

extern AutokeyState g_autokey_state;

#endif /* AUTOKEY_H */
