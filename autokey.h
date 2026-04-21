/*
 * autokey.h - Autokey Security Protocol Header (RFC 5906)
 *
 * IMPORTANT: Autokey is an extension of I-DO (RFC 5905 Section 8.4).
 * According to RFC, they share the same state machine.
 * We use IdoState structure for both I-DO and Autokey.
 *
 * This header provides compatibility macros and functions
 * that wrap IdoState with Autokey naming conventions.
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

#ifndef AUTOKEY_H
#define AUTOKEY_H

#include "ido.h"
#include "ntpd.h"
#include <stdbool.h>
#include <stdint.h>

/* ============================================================================
 * Autokey State Machine States (alias to IdoState_t)
 * ============================================================================
 */

typedef enum {
    AUTOKEY_STATE_IDLE = IDO_STATE_IDLE,
    AUTOKEY_STATE_OFFER_RECEIVED = IDO_STATE_OFFER_RECEIVED,
    AUTOKEY_STATE_RESPONSE_SENT = IDO_STATE_RESPONSE_SENT,
    AUTOKEY_STATE_AUTHENTICATED = IDO_STATE_AUTHENTICATED,
    AUTOKEY_STATE_REJECTED = IDO_STATE_REJECTED
} AutokeyState_t;

/* ============================================================================
 * Autokey Capability Flags (alias to IDO_CAP_*)
 * ============================================================================
 */

#define AUTOKEY_CAP_OFFER IDO_CAP_OFFER
#define AUTOKEY_CAP_RESPONSE IDO_CAP_RESPONSE
#define AUTOKEY_CAP_RESERVED IDO_CAP_RESERVED

/* ============================================================================
 * Autokey State Structure
 * ============================================================================
 *
 * NOTE: Autokey uses IdoState structure directly.
 * This is per RFC 5906 which states Autokey is an extension of I-DO.
 * We provide typedef alias for source code compatibility.
 */

typedef IdoState AutokeyState;

/* ============================================================================
 * Compatibility Macros
 * ============================================================================
 *
 * These macros map autokey_* field access to ido_* field access
 * for backward compatibility with existing code.
 */

#define g_autokey_state g_ido_state

/* Field access compatibility macros */
#define autokey_state ido_state
#define autokey_offer_received ido_offer_received
#define autokey_response_sent ido_response_sent
#define autokey_capabilities ido_capabilities
#define autokey_key_id ido_key_id
#define autokey_key ido_key
#define autokey_enabled ido_enabled
#define autokey_authenticated ido_authenticated

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
 * HMAC-SHA1 Functions (RFC 5906 Section 3.4.2)
 * ============================================================================
 */

/**
 * Compute HMAC-SHA1 digest
 * @param data Input data to authenticate
 * @param data_len Length of input data
 * @param key Key material (20 bytes for HMAC-SHA1)
 * @param key_len Length of key material
 * @param digest Output buffer (20 bytes)
 * @return 0 on success, -1 on error
 */
int autokey_compute_hmac(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len, uint8_t* digest);

/**
 * Compute MAC for NTP packet
 * @param pkt Pointer to NTP packet data
 * @param pkt_len Length of packet data
 * @param key_id Key identifier
 * @return 0 on success, -1 on error
 */
int autokey_compute_mac(const uint8_t* pkt, size_t pkt_len, uint32_t key_id);

/**
 * Verify MAC for NTP packet
 * @param pkt Pointer to NTP packet data
 * @param pkt_len Length of packet data
 * @param key_id Key identifier
 * @return 0 if MAC is valid, -1 otherwise
 */
int autokey_verify_mac(const uint8_t* pkt, size_t pkt_len, uint32_t key_id);

/* ============================================================================
 * Key Management Functions (RFC 5906 Section 3.4.3)
 * ============================================================================
 */

/**
 * Initialize Autokey subsystem
 * @param key_file Path to key file (NULL for memory-only)
 * @param key_id Key identifier (0 for default)
 * @return 0 on success, -1 on error
 */
int autokey_init(const char* key_file, uint32_t key_id);

/**
 * Cleanup Autokey subsystem
 */
void autokey_cleanup(void);

/**
 * Install key (RFC 5906 Section 3.4.3a)
 * @param state Pointer to AutokeyState structure
 * @param key_id Key identifier
 * @param key Key material (20 bytes)
 * @return 0 on success, -1 on error
 */
int autokey_install_key(AutokeyState* state, uint32_t key_id, const uint8_t* key);

/**
 * Rotate key (RFC 5906 Section 3.4.3b)
 * @param state Pointer to AutokeyState structure
 * @param new_key_id New key identifier
 * @param new_key New key material (20 bytes)
 * @return 0 on success, -1 on error
 */
int autokey_rotate_key(AutokeyState* state, uint32_t new_key_id, const uint8_t* new_key);

/**
 * Revoke key (RFC 5906 Section 3.4.3c)
 * @param state Pointer to AutokeyState structure
 * @param key_id Key identifier to revoke
 * @return 0 on success, -1 on error
 */
int autokey_revoke_key(AutokeyState* state, uint32_t key_id);

/**
 * Process Autokey Key Install extension field
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type (should be 0x000B)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 * @return true if processed successfully, false otherwise
 */
bool autokey_process_key_install(AutokeyState* state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data);

/**
 * Process Autokey Key Rotate extension field
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type (should be 0x000C)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 * @return true if processed successfully, false otherwise
 */
bool autokey_process_key_rotate(AutokeyState* state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data);

/**
 * Process Autokey Key Revoke extension field
 * @param state Pointer to AutokeyState structure
 * @param ef_type Extension field type (should be 0x000D)
 * @param ef_length Extension field length
 * @param ef_data Extension field data
 * @return true if processed successfully, false otherwise
 */
bool autokey_process_key_revoke(AutokeyState* state, uint16_t ef_type, uint8_t ef_length, const uint8_t* ef_data);

/* ============================================================================
 * Global Variables
 * ============================================================================
 *
 * NOTE: We use g_ido_state from ido.h for both I-DO and Autokey.
 * This is per RFC 5906 which defines Autokey as extension of I-DO.
 * The g_autokey_state macro maps to g_ido_state for code compatibility.
 */

#endif /* AUTOKEY_H */
