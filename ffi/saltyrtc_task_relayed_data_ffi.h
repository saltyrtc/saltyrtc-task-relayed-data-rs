/**
 * C bindings for saltyrtc-task-relayed-data crate.
 * https://github.com/saltyrtc/saltyrtc-task-relayed-data-rs
 **/

#ifndef saltyrtc_task_relayed_data_bindings_h
#define saltyrtc_task_relayed_data_bindings_h

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define LEVEL_DEBUG 1

#define LEVEL_ERROR 4

#define LEVEL_INFO 2

#define LEVEL_OFF 5

#define LEVEL_TRACE 0

#define LEVEL_WARN 3

/*
 * Result type with all potential connection error codes.
 *
 * If no error happened, the value should be `CONNECT_OK` (0).
 */
enum salty_client_connect_success_t {
  /*
   * No error.
   */
  CONNECT_OK = 0,
  /*
   * One of the arguments was a `null` pointer.
   */
  CONNECT_NULL_ARGUMENT = 1,
  /*
   * The hostname is invalid (probably not UTF-8)
   */
  CONNECT_INVALID_HOST = 2,
  /*
   * TLS related error
   */
  CONNECT_TLS_ERROR = 3,
  /*
   * Certificate related error
   */
  CONNECT_CERTIFICATE_ERROR = 4,
  /*
   * Another connection error
   */
  CONNECT_ERROR = 9,
};
typedef uint8_t salty_client_connect_success_t;

/*
 * Result type with all potential disconnection error codes.
 *
 * If no error happened, the value should be `DISCONNECT_OK` (0).
 */
enum salty_client_disconnect_success_t {
  /*
   * No error.
   */
  DISCONNECT_OK = 0,
  /*
   * One of the arguments was a `null` pointer.
   */
  DISCONNECT_NULL_ARGUMENT = 1,
  /*
   * Invalid close code
   */
  DISCONNECT_BAD_CLOSE_CODE = 2,
  /*
   * Another connection error
   */
  DISCONNECT_ERROR = 9,
};
typedef uint8_t salty_client_disconnect_success_t;

/*
 * Result type with all potential event receiving error codes.
 *
 * If no error happened, the value should be `RECV_OK` (0).
 */
enum salty_client_recv_success_t {
  /*
   * No error.
   */
  RECV_OK = 0,
  /*
   * One of the arguments was a `null` pointer.
   */
  RECV_NULL_ARGUMENT = 1,
  /*
   * No data is available (timeout reached).
   */
  RECV_NO_DATA = 2,
  /*
   * The stream has ended and *SHOULD NOT* be polled again.
   */
  RECV_STREAM_ENDED = 3,
  /*
   * Another receiving error
   */
  RECV_ERROR = 9,
};
typedef uint8_t salty_client_recv_success_t;

/*
 * Result type with all potential error codes.
 *
 * If no error happened, the value should be `SEND_OK` (0).
 */
enum salty_client_send_success_t {
  /*
   * No error.
   */
  SEND_OK = 0,
  /*
   * One of the arguments was a `null` pointer.
   */
  SEND_NULL_ARGUMENT = 1,
  /*
   * Sending failed because the message was invalid
   */
  SEND_MESSAGE_ERROR = 2,
  /*
   * Sending failed
   */
  SEND_ERROR = 9,
};
typedef uint8_t salty_client_send_success_t;

/*
 * Possible event types.
 */
enum salty_event_type_t {
  /*
   * A connection is being established.
   */
  EVENT_CONNECTING = 1,
  /*
   * Server handshake completed.
   */
  EVENT_SERVER_HANDSHAKE_COMPLETED = 2,
  /*
   * Peer handshake completed.
   */
  EVENT_PEER_HANDSHAKE_COMPLETED = 3,
  /*
   * The connection has ended.
   */
  EVENT_DISCONNECTED = 16,
  /*
   * Incoming message.
   */
  EVENT_INCOMING_MSG = 255,
};
typedef uint8_t salty_event_type_t;

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
 * The oneshot channel for closing the connection (receiving end).
 *
 * On the Rust side, this is an `oneshot::Receiver<CloseCode>`.
 */
typedef struct salty_channel_disconnect_rx_t salty_channel_disconnect_rx_t;

/*
 * The oneshot channel for closing the connection (sending end).
 *
 * On the Rust side, this is an `oneshot::Sender<CloseCode>`.
 */
typedef struct salty_channel_disconnect_tx_t salty_channel_disconnect_tx_t;

/*
 * The channel for receiving incoming messages.
 *
 * On the Rust side, this is an `mpsc::UnboundedReceiver<Message>`.
 */
typedef struct salty_channel_receiver_rx_t salty_channel_receiver_rx_t;

/*
 * The channel for sending outgoing messages (receiving end).
 *
 * On the Rust side, this is an `mpsc::UnboundedReceiver<Value>`.
 */
typedef struct salty_channel_sender_rx_t salty_channel_sender_rx_t;

/*
 * The channel for sending outgoing messages (sending end).
 *
 * On the Rust side, this is an `mpsc::UnboundedSender<Value>`.
 */
typedef struct salty_channel_sender_tx_t salty_channel_sender_tx_t;

/*
 * A SaltyRTC client instance.
 *
 * Internally, this is a `Rc<RefCell<SaltyClient>>`.
 */
typedef struct salty_client_t salty_client_t;

/*
 * An event loop instance.
 *
 * The event loop is not thread safe.
 */
typedef struct salty_event_loop_t salty_event_loop_t;

/*
 * A key pair.
 */
typedef struct salty_keypair_t salty_keypair_t;

/*
 * A remote handle to an event loop instance.
 *
 * This type is thread safe.
 */
typedef struct salty_remote_t salty_remote_t;

/*
 * An event (e.g. a connectivity change or an incoming message).
 *
 * If the event type is `EVENT_INCOMING_MSG`, then the `msg_bytes` field will
 * point to the bytes of the decrypted message. Otherwise, the field is `null`.
 *
 * If the event type is `EVENT_DISCONNECTED`, then the `close_code` field will
 * contain the close code. Otherwise, the field is `0`.
 */
typedef struct {
  salty_event_type_t event_type;
  const uint8_t *msg_bytes;
  uintptr_t msg_bytes_len;
  uint16_t close_code;
} salty_event_t;

/*
 * The return value when trying to receive an event.
 *
 * Note: Before accessing `event`, make sure to check the `success` field
 * for errors. If an error occurred, the `event` field will be `null`.
 */
typedef struct {
  salty_client_recv_success_t success;
  const salty_event_t *event;
} salty_client_recv_ret_t;

/*
 * The return value when creating a new client instance.
 *
 * Note: Before accessing `client` or one of the channels, make sure to check
 * the `success` field for errors. If the creation of the client
 * was not successful, then the other pointers will be null.
 */
typedef struct {
  salty_relayed_data_success_t success;
  const salty_client_t *client;
  const salty_channel_receiver_rx_t *receiver_rx;
  const salty_channel_sender_tx_t *sender_tx;
  const salty_channel_sender_rx_t *sender_rx;
  const salty_channel_disconnect_tx_t *disconnect_tx;
  const salty_channel_disconnect_rx_t *disconnect_rx;
} salty_relayed_data_client_ret_t;

/*
 * Free a `salty_channel_disconnect_rx_t` instance.
 */
void salty_channel_disconnect_rx_free(const salty_channel_disconnect_rx_t *ptr);

/*
 * Free a `salty_channel_disconnect_tx_t` instance.
 */
void salty_channel_disconnect_tx_free(const salty_channel_disconnect_tx_t *ptr);

/*
 * Free a `salty_channel_receiver_rx_t` instance.
 */
void salty_channel_receiver_rx_free(const salty_channel_receiver_rx_t *ptr);

/*
 * Free a `salty_channel_sender_rx_t` instance.
 */
void salty_channel_sender_rx_free(const salty_channel_sender_rx_t *ptr);

/*
 * Free a `salty_channel_sender_tx_t` instance.
 */
void salty_channel_sender_tx_free(const salty_channel_sender_tx_t *ptr);

/*
 * Connect to the specified SaltyRTC server, do the server and peer handshake
 * and run the task loop.
 *
 * This is a blocking call. It will end once the connection has been terminated.
 * You should probably run this in a separate thread.
 *
 * Parameters:
 *     host (`*c_char`, null terminated, borrowed):
 *         Null terminated UTF-8 encoded C string containing the SaltyRTC server hostname.
 *     port (`*uint16_t`, copied):
 *         SaltyRTC server port.
 *     client (`*salty_client_t`, borrowed):
 *         Pointer to a `salty_client_t` instance.
 *     event_loop (`*salty_event_loop_t`, borrowed):
 *         The event loop that is also associated with the task.
 *     sender_rx (`*salty_channel_sender_rx_t`, moved):
 *         The receiving end of the channel for outgoing messages.
 *         This object is returned when creating a client instance.
 *     disconnect_rx (`*salty_channel_disconnect_rx_t`, moved):
 *         The receiving end of the channel for closing the connection.
 *         This object is returned when creating a client instance.
 *     timeout_s (`uint16_t`, copied):
 *         Connection and handshake timeout in seconds. Set value to `0` for no timeout.
 *     ca_cert (`*uint8_t` or `NULL`, borrowed):
 *         Optional pointer to bytes of a DER encoded CA certificate.
 *         When no certificate is set, the OS trust chain is used.
 *     ca_cert_len (`uint32_t`, copied):
 *         When the `ca_cert` argument is not `NULL`, then this must be
 *         set to the number of certificate bytes. Otherwise, set it to 0.
 */
salty_client_connect_success_t salty_client_connect(const char *host,
                                                    uint16_t port,
                                                    const salty_client_t *client,
                                                    const salty_event_loop_t *event_loop,
                                                    const salty_channel_sender_rx_t *sender_rx,
                                                    const salty_channel_disconnect_rx_t *disconnect_rx,
                                                    uint16_t timeout_s,
                                                    const uint8_t *ca_cert,
                                                    uint32_t ca_cert_len);

/*
 * Close the connection.
 *
 * Depending on whether this succeeds or not, the `disconnect_tx` instance is
 * freed or not:
 *
 * - DISCONNECT_OK: The `disconnect_tx` instance was freed
 * - DISCONNECT_NULL_ARGUMENT: The `disconnect_tx` instance was not freed
 * - DISCONNECT_BAD_CLOSE_CODE: The `disconnect_tx` instance was not freed
 * - DISCONNECT_ERROR: The `disconnect_tx` instance was freed
 *
 * Parameters:
 *     disconnect_tx (`*salty_channel_disconnect_tx_t`, borrowed or moved):
 *         The sending end of the channel for closing the connection.
 *         This object is returned when creating a client instance.
 *     close_code (`uint16_t`, copied):
 *         The close code according to the SaltyRTC protocol specification.
 */
salty_client_disconnect_success_t salty_client_disconnect(const salty_channel_disconnect_tx_t *disconnect_tx,
                                                          uint16_t close_code);

/*
 * Receive an event from the outgoing channel.
 *
 * Parameters:
 *     receiver_rx (`*salty_channel_receiver_rx_t`, borrowed):
 *         The receiving end of the channel for incoming events.
 *     timeout_ms (`*uint32_t`, borrowed):
 *         - If this is `null`, then the function call will block.
 *         - If this is `0`, then the function will never block. It will either return an event
 *         or `RECV_NO_DATA`.
 *         - If this is a value > 0, then the specified timeout in milliseconds will be used.
 *         Either an event or `RECV_NO_DATA` (in the case of a timeout) will be returned.
 */
salty_client_recv_ret_t salty_client_recv_event(const salty_channel_receiver_rx_t *receiver_rx,
                                                const uint32_t *timeout_ms);

/*
 * Free an event loop instance.
 */
void salty_client_recv_ret_free(salty_client_recv_ret_t recv_ret);

/*
 * Send a message through the outgoing channel.
 *
 * Parameters:
 *     sender_tx (`*salty_channel_sender_tx_t`, borrowed):
 *         The sending end of the channel for outgoing messages.
 *     msg (`*uint8_t`, borrowed):
 *         Pointer to the message bytes.
 *     msg_len (`uint32_t`, copied):
 *         Length of the message in bytes.
 */
salty_client_send_success_t salty_client_send_bytes(const salty_channel_sender_tx_t *sender_tx,
                                                    const uint8_t *msg,
                                                    uint32_t msg_len);

/*
 * Free an event loop instance.
 */
void salty_event_loop_free(const salty_event_loop_t *ptr);

/*
 * Free an event loop remote handle.
 */
void salty_event_loop_free_remote(const salty_remote_t *ptr);

/*
 * Return a remote handle from an event loop instance.
 *
 * Thread safety:
 *     The `salty_remote_t` instance may be used from any thread.
 * Ownership:
 *     The `salty_remote_t` instance must be freed through `salty_event_loop_free_remote`,
 *     or by moving it into a `salty_client_t` instance.
 * Returns:
 *     A reference to the remote handle.
 *     If the pointer passed in is `null`, an error is logged and `null` is returned.
 */
const salty_remote_t *salty_event_loop_get_remote(const salty_event_loop_t *ptr);

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
const salty_event_loop_t *salty_event_loop_new(void);

/*
 * Free a `KeyPair` instance.
 *
 * Note: If you move the `salty_keypair_t` instance into a `salty_client_t` instance,
 * you do not need to free it explicitly. It is dropped when the `salty_client_t`
 * instance is freed.
 */
void salty_keypair_free(const salty_keypair_t *ptr);

/*
 * Create a new `KeyPair` instance and return an opaque pointer to it.
 */
const salty_keypair_t *salty_keypair_new(void);

/*
 * Get the public key from a `salty_keypair_t` instance.
 *
 * Returns:
 *     A null pointer if the parameter is null.
 *     Pointer to a 32 byte `uint8_t` array otherwise.
 */
const uint8_t *salty_keypair_public_key(const salty_keypair_t *ptr);

/*
 * Change the log level of the logger.
 *
 * Parameters:
 *     level (uint8_t, copied):
 *         The log level, must be in the range 0 (TRACE) to 5 (OFF).
 *         See `LEVEL_*` constants for reference.
 * Returns:
 *     A boolean indicating whether logging was updated successfully.
 *     If updating the logger failed, an error message will be written to stdout.
 */
bool salty_log_change_level(uint8_t level);

/*
 * Initialize logging to stdout with log messages up to the specified log level.
 *
 * Parameters:
 *     level (uint8_t, copied):
 *         The log level, must be in the range 0 (TRACE) to 5 (OFF).
 *         See `LEVEL_*` constants for reference.
 * Returns:
 *     A boolean indicating whether logging was setup successfully.
 *     If setting up the logger failed, an error message will be written to stdout.
 */
bool salty_log_init(uint8_t level);

/*
 * Get a pointer to the auth token bytes from a `salty_client_t` instance.
 *
 * Ownership:
 *     The memory is still owned by the `salty_client_t` instance.
 *     Do not reuse the reference after the `salty_client_t` instance has been freed!
 * Returns:
 *     A null pointer if the parameter is null, if no auth token is set on the client
 *     or if the rc cannot be borrowed.
 *     Pointer to a 32 byte `uint8_t` array otherwise.
 */
const uint8_t *salty_relayed_data_client_auth_token(const salty_client_t *ptr);

/*
 * Free a SaltyRTC client with the Relayed Data task.
 */
void salty_relayed_data_client_free(const salty_client_t *ptr);

/*
 * Initialize a new SaltyRTC client as initiator with the Relayed Data task.
 *
 * Parameters:
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
salty_relayed_data_client_ret_t salty_relayed_data_initiator_new(const salty_keypair_t *keypair,
                                                                 const salty_remote_t *remote,
                                                                 uint32_t ping_interval_seconds);

/*
 * Initialize a new SaltyRTC client as responder with the Relayed Data task.
 *
 * Parameters:
 *     keypair (`*salty_keypair_t`, moved):
 *         Pointer to a key pair.
 *     remote (`*salty_remote_t`, moved):
 *         Pointer to an event loop remote handle.
 *     ping_interval_seconds (`uint32_t`, copied):
 *         Request that the server sends a WebSocket ping message at the specified interval.
 *         Set this argument to `0` to disable ping messages.
 *     initiator_pubkey (`*uint8_t`, borrowed):
 *         Public key of the initiator. A 32 byte `uint8_t` array.
 *     auth_token (`*uint8_t` or `null`, borrowed):
 *         One-time auth token from the initiator. If set, this must be a 32 byte `uint8_t` array.
 *         Set this to `null` when restoring a trusted session.
 * Returns:
 *     A `salty_relayed_data_client_ret_t` struct.
 */
salty_relayed_data_client_ret_t salty_relayed_data_responder_new(const salty_keypair_t *keypair,
                                                                 const salty_remote_t *remote,
                                                                 uint32_t ping_interval_seconds,
                                                                 const uint8_t *initiator_pubkey,
                                                                 const uint8_t *auth_token);

#endif /* saltyrtc_task_relayed_data_bindings_h */
