/**
 * C bindings for saltyrtc-task-relayed-data crate.
 * https://github.com/saltyrtc/saltyrtc-task-relayed-data-rs
 **/

#ifndef saltyrtc_task_relayed_data_bindings_h
#define saltyrtc_task_relayed_data_bindings_h

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/*
 * Result type with all potential error codes.
 *
 * If no error happened, the value should be `OK` (0).
 */
enum salty_relayed_data_success_t {
  /*
   * No error.
   */
  OK = 0,
  /*
   * One of the arguments was a `null` pointer.
   */
  NULL_ARGUMENT = 1,
  /*
   * Creation of the object failed.
   */
  CREATE_FAILED = 2,
  /*
   * The public key bytes are not valid.
   */
  PUBKEY_INVALID = 3,
  /*
   * The auth token bytes are not valid.
   */
  AUTH_TOKEN_INVALID = 4,
};
typedef uint8_t salty_relayed_data_success_t;

/*
 * The channel for receiving incoming messages.
 */
typedef struct salty_channel_receiver_t salty_channel_receiver_t;

/*
 * A SaltyRTC client instance.
 */
typedef struct salty_client_t salty_client_t;

/*
 * An event loop instance.
 */
typedef struct salty_event_loop_t salty_event_loop_t;

/*
 * A key pair.
 */
typedef struct salty_keypair_t salty_keypair_t;

/*
 * A remote handle to an event loop instance.
 */
typedef struct salty_remote_t salty_remote_t;

/*
 * The return value when creating a new client instance.
 *
 * Note: Before accessing `client` or `rx_chan`, make sure to check
 * the `success` field for errors. If the creation of the client
 * was not successful, then the `client` and `rx_chan` pointers will be null.
 */
typedef struct {
  salty_relayed_data_success_t success;
  salty_client_t *client;
  salty_channel_receiver_t *rx_chan;
} salty_relayed_data_client_ret_t;

/*
 * Free a `salty_channel_receiver_t` instance.
 */
void salty_channel_receiver_free(salty_channel_receiver_t *ptr);

/*
 * Free an event loop instance.
 */
void salty_event_loop_free(salty_event_loop_t *ptr);

/*
 * Free an event loop remote handle.
 */
void salty_event_loop_free_remote(salty_remote_t *ptr);

/*
 * Return a remote handle from an event loop instance.
 *
 * Thread safety:
 *     The `salty_remote_t` instance may be used from any thread.
 * Ownership:
 *     The `salty_remote_t` instance must be freed through `salty_event_loop_free_remote`.
 * Returns:
 *     A reference to the remote handle.
 *     If the pointer passed in is `null`, an error is logged and `null` is returned.
 */
salty_remote_t *salty_event_loop_get_remote(salty_event_loop_t *ptr);

/*
 * Create a new event loop instance.
 *
 * In the background, this will instantiate a Tokio reactor core.
 *
 * Returns:
 *     Either a pointer to the reactor core, or `null`
 *     if creation of the event loop failed.
 *     In the case of a failure, the error will be logged.
 */
salty_event_loop_t *salty_event_loop_new(void);

/*
 * Free a `KeyPair` instance.
 *
 * Note: If you move the `salty_keypair_t` instance into a `salty_client_t` instance,
 * you do not need to free it explicitly. It is dropped when the `salty_client_t`
 * instance is freed.
 */
void salty_keypair_free(salty_keypair_t *ptr);

/*
 * Create a new `KeyPair` instance and return an opaque pointer to it.
 */
salty_keypair_t *salty_keypair_new(void);

/*
 * Get the public key from a `salty_keypair_t` instance.
 *
 * Returns:
 *     A null pointer if the parameter is null.
 *     Pointer to a 32 byte `uint8_t` array otherwise.
 */
const uint8_t *salty_keypair_public_key(const salty_keypair_t *ptr);

/*
 * Get a pointer to the auth token bytes from a `salty_client_t` instance.
 *
 * Ownership:
 *     The memory is still owned by the `salty_client_t` instance.
 *     Do not reuse the reference after the `salty_client_t` instance has been freed!
 * Returns:
 *     A null pointer if the parameter is null or if no auth token is set on the client.
 *     Pointer to a 32 byte `uint8_t` array otherwise.
 */
const uint8_t *salty_relayed_data_client_auth_token(const salty_client_t *ptr);

/*
 * Free a SaltyRTC client with the Relayed Data task.
 */
void salty_relayed_data_client_free(salty_client_t *ptr);

/*
 * Initialize a new SaltyRTC client as initiator with the Relayed Data task.
 *
 * Arguments:
 *     keypair (`*salty_keypair_t`, moved):
 *         Pointer to a key pair.
 *     remote (`*salty_remote_t`, moved):
 *         Pointer to an event loop remote handle.
 *     ping_interval_seconds (`uint32_t`, copied):
 *         Request that the server sends a WebSocket ping message at the specified interval.
 *         Set this argument to `0` to disable ping messages.
 * Returns:
 *     A `salty_relayed_data_client_ret_t` struct.
 */
salty_relayed_data_client_ret_t salty_relayed_data_initiator_new(salty_keypair_t *keypair,
                                                                 salty_remote_t *remote,
                                                                 uint32_t ping_interval_seconds);

/*
 * Initialize a new SaltyRTC client as responder with the Relayed Data task.
 *
 * Arguments:
 *     keypair (`*salty_keypair_t`, moved):
 *         Pointer to a key pair.
 *     remote (`*salty_remote_t`, moved):
 *         Pointer to an event loop remote handle.
 *         The ownership of this data is moved into the client instance.
 *     ping_interval_seconds (`uint32_t`, copied):
 *         Request that the server sends a WebSocket ping message at the specified interval.
 *         Set this argument to `0` to disable ping messages.
 *     initiator_pubkey (`const *uint8_t`, borrowed):
 *         Public key of the initiator. A 32 byte `uint8_t` array.
 *     auth_token (`const *uint8_t` or `null`, borrowed):
 *         One-time auth token from the initiator. If set, this must be a 32 byte `uint8_t` array.
 *         Set this to `null` when restoring a trusted session.
 * Returns:
 *     A `salty_relayed_data_client_ret_t` struct.
 */
salty_relayed_data_client_ret_t salty_relayed_data_responder_new(salty_keypair_t *keypair,
                                                                 salty_remote_t *remote,
                                                                 uint32_t ping_interval_seconds,
                                                                 const uint8_t *initiator_pubkey,
                                                                 const uint8_t *auth_token);

#endif /* saltyrtc_task_relayed_data_bindings_h */
