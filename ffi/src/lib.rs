//! FFI bindings for the Relayed Data Task.
//!
//! The bindings currently wrap the entire SaltyRTC client API.
//! The downside of this is that only one task can be specified, not multiple.
//! That's a problem that can be solved later on.
//!
//! The implementation makes use of the opaque pointer pattern.
//!
//! A note on pointers: All const pointers returned by Rust functions should not be modified
//! outside of Rust functions.
//!
//! Ultimately, these bindings allow C compatible programs to do the following things:
//!
//! - Instantiate a SaltyRTC client
//! - Connect to a server, do the server and peer handshake
//! - Send outgoing messages
//! - Receive incoming messages
//! - Receive events (like connection loss, for example)
//! - Terminate the connection
#![allow(non_camel_case_types)]

#[macro_use] extern crate lazy_static;
extern crate libc;
#[macro_use] extern crate log;
extern crate log4rs;
extern crate rmp_serde;
extern crate saltyrtc_client;
extern crate saltyrtc_task_relayed_data;
extern crate tokio_core;
extern crate tokio_timer;

mod connection;
mod constants;
mod nonblocking;
pub mod saltyrtc_client_ffi;

use std::cell::RefCell;
use std::ffi::CStr;
use std::io::{BufReader, Read};
use std::mem;
use std::ptr;
use std::rc::Rc;
use std::slice;
use std::time::Duration;

use libc::{uint8_t, uint16_t, uint32_t, uintptr_t, c_char};
use rmp_serde as rmps;
use saltyrtc_client::{SaltyClient, SaltyClientBuilder, CloseCode};
use saltyrtc_client::crypto::{KeyPair, PublicKey, AuthToken};
use saltyrtc_client::dep::futures::{Future, Stream, Sink};
use saltyrtc_client::dep::futures::future::Either;
use saltyrtc_client::dep::futures::sync::{mpsc, oneshot};
use saltyrtc_client::dep::native_tls::{TlsConnector, Protocol, Certificate};
use saltyrtc_client::dep::rmpv::Value;
use saltyrtc_client::dep::rmpv::decode::read_value;
use saltyrtc_client::tasks::{BoxedTask, Task};
pub use saltyrtc_client_ffi::{salty_client_t, salty_keypair_t, salty_remote_t, salty_event_loop_t};
use saltyrtc_task_relayed_data::{RelayedDataTask, Message};
use tokio_core::reactor::{Core, Remote};
use tokio_timer::Timer;

use connection::Either3;
pub use constants::*;


// *** TYPES *** //

/// Result type with all potential error codes.
///
/// If no error happened, the value should be `OK` (0).
#[repr(u8)]
#[no_mangle]
#[derive(Debug, PartialEq, Eq)]
pub enum salty_relayed_data_success_t {
    /// No error.
    OK = 0,

    /// One of the arguments was a `null` pointer.
    NULL_ARGUMENT = 1,

    /// Creation of the object failed.
    CREATE_FAILED = 2,

    /// The public key bytes are not valid.
    PUBKEY_INVALID = 3,

    /// The auth token bytes are not valid.
    AUTH_TOKEN_INVALID = 4,

    /// The trusted key bytes are not valid.
    TRUSTED_KEY_INVALID = 5,
}

/// The return value when creating a new client instance.
///
/// Note: Before accessing `client` or one of the channels, make sure to check
/// the `success` field for errors. If the creation of the client
/// was not successful, then the other pointers will be null.
#[repr(C)]
#[no_mangle]
pub struct salty_relayed_data_client_ret_t {
    pub success: salty_relayed_data_success_t,
    pub client: *const salty_client_t,
    pub receiver_rx: *const salty_channel_receiver_rx_t,
    pub sender_tx: *const salty_channel_sender_tx_t,
    pub sender_rx: *const salty_channel_sender_rx_t,
    pub disconnect_tx: *const salty_channel_disconnect_tx_t,
    pub disconnect_rx: *const salty_channel_disconnect_rx_t,
}

/// The channel for receiving incoming messages.
///
/// On the Rust side, this is an `mpsc::UnboundedReceiver<Message>`.
#[no_mangle]
pub enum salty_channel_receiver_rx_t {}

/// The channel for sending outgoing messages (sending end).
///
/// On the Rust side, this is an `mpsc::UnboundedSender<Value>`.
#[no_mangle]
pub enum salty_channel_sender_tx_t {}

/// The channel for sending outgoing messages (receiving end).
///
/// On the Rust side, this is an `mpsc::UnboundedReceiver<Value>`.
#[no_mangle]
pub enum salty_channel_sender_rx_t {}

/// The oneshot channel for closing the connection (sending end).
///
/// On the Rust side, this is an `oneshot::Sender<CloseCode>`.
#[no_mangle]
pub enum salty_channel_disconnect_tx_t {}

/// The oneshot channel for closing the connection (receiving end).
///
/// On the Rust side, this is an `oneshot::Receiver<CloseCode>`.
#[no_mangle]
pub enum salty_channel_disconnect_rx_t {}

/// Result type with all potential connection error codes.
///
/// If no error happened, the value should be `CONNECT_OK` (0).
#[repr(u8)]
#[no_mangle]
#[derive(Debug, PartialEq, Eq)]
pub enum salty_client_connect_success_t {
    /// No error.
    CONNECT_OK = 0,

    /// One of the arguments was a `null` pointer.
    CONNECT_NULL_ARGUMENT = 1,

    /// The hostname is invalid (probably not UTF-8)
    CONNECT_INVALID_HOST = 2,

    /// TLS related error
    CONNECT_TLS_ERROR = 3,

    /// Certificate related error
    CONNECT_CERTIFICATE_ERROR = 4,

    /// Another connection error
    CONNECT_ERROR = 9,
}

/// Result type with all potential disconnection error codes.
///
/// If no error happened, the value should be `DISCONNECT_OK` (0).
#[repr(u8)]
#[no_mangle]
#[derive(Debug, PartialEq, Eq)]
pub enum salty_client_disconnect_success_t {
    /// No error.
    DISCONNECT_OK = 0,

    /// One of the arguments was a `null` pointer.
    DISCONNECT_NULL_ARGUMENT = 1,

    /// Invalid close code
    DISCONNECT_BAD_CLOSE_CODE = 2,

    /// Another connection error
    DISCONNECT_ERROR = 9,
}

/// Result type with all potential error codes.
///
/// If no error happened, the value should be `SEND_OK` (0).
#[repr(u8)]
#[no_mangle]
#[derive(Debug, PartialEq, Eq)]
pub enum salty_client_send_success_t {
    /// No error.
    SEND_OK = 0,

    /// One of the arguments was a `null` pointer.
    SEND_NULL_ARGUMENT = 1,

    /// Sending failed because the message was invalid
    SEND_MESSAGE_ERROR = 2,

    /// Sending failed
    SEND_ERROR = 9,
}

/// Possible event types.
#[repr(u8)]
#[no_mangle]
#[derive(Debug, PartialEq, Eq)]
pub enum salty_event_type_t {
    /// A connection is being established.
    EVENT_CONNECTING = 0x01,

    /// Server handshake completed.
    EVENT_SERVER_HANDSHAKE_COMPLETED = 0x02,

    /// Peer handshake completed.
    EVENT_PEER_HANDSHAKE_COMPLETED = 0x03,

    /// The connection has ended.
    EVENT_DISCONNECTED = 0x10,

    /// Incoming message.
    EVENT_INCOMING_MSG = 0xff,
}

/// An event (e.g. a connectivity change or an incoming message).
///
/// If the event type is `EVENT_INCOMING_MSG`, then the `msg_bytes` field will
/// point to the bytes of the decrypted message. Otherwise, the field is `null`.
///
/// If the event type is `EVENT_DISCONNECTED`, then the `close_code` field will
/// contain the close code. Otherwise, the field is `0`.
#[repr(C)]
#[no_mangle]
pub struct salty_event_t {
    event_type: salty_event_type_t,
    msg_bytes: *const uint8_t,
    msg_bytes_len: uintptr_t,
    close_code: uint16_t,
}

/// Result type with all potential event receiving error codes.
///
/// If no error happened, the value should be `RECV_OK` (0).
#[repr(u8)]
#[no_mangle]
#[derive(Debug, PartialEq, Eq)]
pub enum salty_client_recv_success_t {
    /// No error.
    RECV_OK = 0,

    /// One of the arguments was a `null` pointer.
    RECV_NULL_ARGUMENT = 1,

    /// No data is available (timeout reached).
    RECV_NO_DATA = 2,

    /// The stream has ended and *SHOULD NOT* be polled again.
    RECV_STREAM_ENDED = 3,

    /// Another receiving error
    RECV_ERROR = 9,
}

/// The return value when trying to receive an event.
///
/// Note: Before accessing `event`, make sure to check the `success` field
/// for errors. If an error occurred, the `event` field will be `null`.
#[repr(C)]
#[no_mangle]
pub struct salty_client_recv_ret_t {
    pub success: salty_client_recv_success_t,
    pub event: *const salty_event_t,
}


// *** HELPER FUNCTIONS *** //

/// Helper function to return error values when creating a client instance.
fn make_client_create_error(reason: salty_relayed_data_success_t) -> salty_relayed_data_client_ret_t {
    salty_relayed_data_client_ret_t {
        success: reason,
        client: ptr::null(),
        receiver_rx: ptr::null(),
        sender_tx: ptr::null(),
        sender_rx: ptr::null(),
        disconnect_tx: ptr::null(),
        disconnect_rx: ptr::null(),
    }
}


/// Helper function to return error values when receiving events.
fn make_event_recv_error(reason: salty_client_recv_success_t) -> salty_client_recv_ret_t {
    salty_client_recv_ret_t {
        success: reason,
        event: ptr::null(),
    }
}

struct ClientBuilderRet {
    builder: SaltyClientBuilder,
    receiver_rx: mpsc::UnboundedReceiver<Message>,
    sender_tx: mpsc::UnboundedSender<Value>,
    sender_rx: mpsc::UnboundedReceiver<Value>,
    disconnect_tx: oneshot::Sender<CloseCode>,
    disconnect_rx: oneshot::Receiver<CloseCode>,
}

/// Helper function to parse arguments and to create a new `SaltyClientBuilder`.
unsafe fn create_client_builder(
    keypair: *const salty_keypair_t,
    remote: *const salty_remote_t,
    ping_interval_seconds: uint32_t,
) -> Result<ClientBuilderRet, salty_relayed_data_success_t> {
    // Null checks
    if keypair.is_null() {
        error!("Keypair pointer is null");
        return Err(salty_relayed_data_success_t::NULL_ARGUMENT);
    }
    if remote.is_null() {
        error!("Remote pointer is null");
        return Err(salty_relayed_data_success_t::NULL_ARGUMENT);
    }

    // Recreate pointer instances
    let keypair = Box::from_raw(keypair as *mut KeyPair);
    let remote = Box::from_raw(remote as *mut Remote);

    // Create communication channels
    // TODO: The sender should not be created here, it should be extracted from the task!
    let (receiver_tx, receiver_rx) = mpsc::unbounded();
    let (sender_tx, sender_rx) = mpsc::unbounded();
    let (disconnect_tx, disconnect_rx) = oneshot::channel();

    // Instantiate task
    let task = RelayedDataTask::new(*remote, receiver_tx);

    // Determine ping interval
    let interval = match ping_interval_seconds {
        0 => None,
        secs => Some(Duration::from_secs(secs as u64))
    };

    // Create builder instance
    let builder = SaltyClient::build(*keypair)
        .add_task(Box::new(task) as BoxedTask)
        .with_ping_interval(interval);

    Ok(ClientBuilderRet {
        builder,
        receiver_rx,
        sender_tx,
        sender_rx,
        disconnect_tx,
        disconnect_rx,
    })
}


// *** MAIN FUNCTIONALITY *** //

/// Initialize a new SaltyRTC client as initiator with the Relayed Data task.
///
/// Parameters:
///     keypair (`*salty_keypair_t`, moved):
///         Pointer to a key pair.
///     remote (`*salty_remote_t`, moved):
///         Pointer to an event loop remote handle.
///     ping_interval_seconds (`uint32_t`, copied):
///         Request that the server sends a WebSocket ping message at the specified interval.
///         Set this argument to `0` to disable ping messages.
///     trusted_responder_key (`*uint8_t` or `null`, borrowed):
///         The trusted responder public key. If set, this must be a pointer to a 32 byte
///         `uint8_t` array. Set this to null when not restoring a trusted session.
/// Returns:
///     A `salty_relayed_data_client_ret_t` struct.
#[no_mangle]
pub unsafe extern "C" fn salty_relayed_data_initiator_new(
    keypair: *const salty_keypair_t,
    remote: *const salty_remote_t,
    ping_interval_seconds: uint32_t,
    trusted_responder_key: *const uint8_t,
) -> salty_relayed_data_client_ret_t {
    // Parse arguments and create SaltyRTC builder
    let ret = match create_client_builder(keypair, remote, ping_interval_seconds) {
        Ok(val) => val,
        Err(reason) => return make_client_create_error(reason),
    };

    // Parse trusted responder key
    let trusted_key_opt = if trusted_responder_key.is_null() {
        None
    } else {
        // Get slice
        let trusted_key_slice: &[u8] = slice::from_raw_parts(trusted_responder_key, 32);

        // Just to rule out stupid mistakes, make sure that the public key is not all-zero
        if trusted_key_slice.iter().all(|&x| x == 0) {
            error!("Trusted key bytes are all zero!");
            return make_client_create_error(salty_relayed_data_success_t::TRUSTED_KEY_INVALID);
        }

        // Parse
        match PublicKey::from_slice(trusted_key_slice) {
            Some(key) => Some(key),
            None => {
                error!("Could not parse trusted key bytes");
                return make_client_create_error(salty_relayed_data_success_t::TRUSTED_KEY_INVALID);
            }
        }
    };

    // Create client instance
    let client_res = match trusted_key_opt {
        Some(key) => ret.builder.initiator_trusted(key),
        None => ret.builder.initiator(),
    };
    let client = match client_res {
        Ok(client) => client,
        Err(e) => {
            error!("Could not instantiate SaltyClient: {}", e);
            return make_client_create_error(salty_relayed_data_success_t::CREATE_FAILED);
        },
    };

    salty_relayed_data_client_ret_t {
        success: salty_relayed_data_success_t::OK,
        client: Rc::into_raw(Rc::new(RefCell::new(client))) as *const salty_client_t,
        receiver_rx: Box::into_raw(Box::new(ret.receiver_rx)) as *const salty_channel_receiver_rx_t,
        sender_tx: Box::into_raw(Box::new(ret.sender_tx)) as *const salty_channel_sender_tx_t,
        sender_rx: Box::into_raw(Box::new(ret.sender_rx)) as *const salty_channel_sender_rx_t,
        disconnect_tx: Box::into_raw(Box::new(ret.disconnect_tx)) as *const salty_channel_disconnect_tx_t,
        disconnect_rx: Box::into_raw(Box::new(ret.disconnect_rx)) as *const salty_channel_disconnect_rx_t,
    }
}

/// Initialize a new SaltyRTC client as responder with the Relayed Data task.
///
/// Parameters:
///     keypair (`*salty_keypair_t`, moved):
///         Pointer to a key pair.
///     remote (`*salty_remote_t`, moved):
///         Pointer to an event loop remote handle.
///     ping_interval_seconds (`uint32_t`, copied):
///         Request that the server sends a WebSocket ping message at the specified interval.
///         Set this argument to `0` to disable ping messages.
///     initiator_pubkey (`*uint8_t`, borrowed):
///         Public key of the initiator. A 32 byte `uint8_t` array.
///     auth_token (`*uint8_t` or `null`, borrowed):
///         One-time auth token from the initiator. If set, this must be a pointer
///         to a 32 byte `uint8_t` array. Set this to `null` when restoring a trusted session.
/// Returns:
///     A `salty_relayed_data_client_ret_t` struct.
#[no_mangle]
pub unsafe extern "C" fn salty_relayed_data_responder_new(
    keypair: *const salty_keypair_t,
    remote: *const salty_remote_t,
    ping_interval_seconds: uint32_t,
    initiator_pubkey: *const uint8_t,
    auth_token: *const uint8_t,
) -> salty_relayed_data_client_ret_t {
    // Parse arguments and create SaltyRTC builder
    let ret = match create_client_builder(keypair, remote, ping_interval_seconds) {
        Ok(val) => val,
        Err(reason) => return make_client_create_error(reason),
    };

    // Get public key slice
    if initiator_pubkey.is_null() {
        error!("Initiator public key is a null pointer");
        return make_client_create_error(salty_relayed_data_success_t::NULL_ARGUMENT);
    }
    let pubkey_slice: &[u8] = slice::from_raw_parts(initiator_pubkey, 32);

    // Just to rule out stupid mistakes, make sure that the public key is not all-zero
    if pubkey_slice.iter().all(|&x| x == 0) {
        error!("Public key bytes are all zero!");
        return make_client_create_error(salty_relayed_data_success_t::PUBKEY_INVALID);
    }

    // Parse public key
    let pubkey = match PublicKey::from_slice(pubkey_slice) {
        Some(pubkey) => pubkey,
        None => {
            error!("Public key bytes could not be parsed");
            return make_client_create_error(salty_relayed_data_success_t::PUBKEY_INVALID);
        }
    };

    // Parse auth token
    let auth_token_opt = if auth_token.is_null() {
        None
    } else {
        // Get slice
        let auth_token_slice: &[u8] = slice::from_raw_parts(auth_token, 32);

        // Just to rule out stupid mistakes, make sure that the token is not all-zero
        if auth_token_slice.iter().all(|&x| x == 0) {
            error!("Auth token bytes are all zero!");
            return make_client_create_error(salty_relayed_data_success_t::AUTH_TOKEN_INVALID);
        }

        // Parse
        match AuthToken::from_slice(auth_token_slice) {
            Ok(token) => Some(token),
            Err(e) => {
                error!("Could not parse auth token bytes: {}", e);
                return make_client_create_error(salty_relayed_data_success_t::AUTH_TOKEN_INVALID);
            }
        }
    };

    // Create client instance
    let client_res = match auth_token_opt {
        // An auth token was set. Initiate a new session.
        Some(token) => ret.builder.responder(pubkey, token),
        // No auth token was set. Restore trusted session.
        None => ret.builder.responder_trusted(pubkey),
    };
    let client = match client_res {
        Ok(client) => client,
        Err(e) => {
            error!("Could not instantiate SaltyClient: {}", e);
            return make_client_create_error(salty_relayed_data_success_t::CREATE_FAILED);
        },
    };

    salty_relayed_data_client_ret_t {
        success: salty_relayed_data_success_t::OK,
        client: Rc::into_raw(Rc::new(RefCell::new(client))) as *const salty_client_t,
        receiver_rx: Box::into_raw(Box::new(ret.receiver_rx)) as *const salty_channel_receiver_rx_t,
        sender_tx: Box::into_raw(Box::new(ret.sender_tx)) as *const salty_channel_sender_tx_t,
        sender_rx: Box::into_raw(Box::new(ret.sender_rx)) as *const salty_channel_sender_rx_t,
        disconnect_tx: Box::into_raw(Box::new(ret.disconnect_tx)) as *const salty_channel_disconnect_tx_t,
        disconnect_rx: Box::into_raw(Box::new(ret.disconnect_rx)) as *const salty_channel_disconnect_rx_t,
    }
}

/// Get a pointer to the auth token bytes from a `salty_client_t` instance.
///
/// Ownership:
///     The memory is still owned by the `salty_client_t` instance.
///     Do not reuse the reference after the `salty_client_t` instance has been freed!
/// Returns:
///     A null pointer if the parameter is null, if no auth token is set on the client
///     or if the rc cannot be borrowed.
///     Pointer to a 32 byte `uint8_t` array otherwise.
#[no_mangle]
pub unsafe extern "C" fn salty_relayed_data_client_auth_token(
    ptr: *const salty_client_t,
) -> *const uint8_t {
    if ptr.is_null() {
        error!("Tried to dereference a null pointer");
        return ptr::null();
    }

    // Recreate Rc from pointer
    let client_rc: Rc<RefCell<SaltyClient>> = Rc::from_raw(ptr as *const RefCell<SaltyClient>);

    // Determine pointer to auth token
    let retval = match client_rc.try_borrow() {
        Ok(client_ref) => match client_ref.auth_token() {
            Some(token) => token.secret_key_bytes().as_ptr(),
            None => ptr::null(),
        },
        Err(e) => {
            error!("Could not borrow client RC: {}", e);
            ptr::null()
        }
    };

    // We must ensure that the Rc is not dropped, otherwise – if it's the last reference to
    // the underlying data – the data on the heap would be dropped too.
    mem::forget(client_rc);

    retval
}

/// Free a SaltyRTC client with the Relayed Data task.
#[no_mangle]
pub unsafe extern "C" fn salty_relayed_data_client_free(
    ptr: *const salty_client_t,
) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Rc::from_raw(ptr as *const RefCell<SaltyClient>);
}

/// Free a `salty_channel_receiver_rx_t` instance.
#[no_mangle]
pub unsafe extern "C" fn salty_channel_receiver_rx_free(
    ptr: *const salty_channel_receiver_rx_t,
) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut mpsc::UnboundedReceiver<Message>);
}

/// Free a `salty_channel_sender_tx_t` instance.
#[no_mangle]
pub unsafe extern "C" fn salty_channel_sender_tx_free(
    ptr: *const salty_channel_sender_tx_t,
) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut mpsc::UnboundedSender<Value>);
}

/// Free a `salty_channel_sender_rx_t` instance.
#[no_mangle]
pub unsafe extern "C" fn salty_channel_sender_rx_free(
    ptr: *const salty_channel_sender_rx_t,
) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut mpsc::UnboundedReceiver<Value>);
}

/// Free a `salty_channel_disconnect_tx_t` instance.
#[no_mangle]
pub unsafe extern "C" fn salty_channel_disconnect_tx_free(
    ptr: *const salty_channel_disconnect_tx_t,
) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut oneshot::Sender<CloseCode>);
}

/// Free a `salty_channel_disconnect_rx_t` instance.
#[no_mangle]
pub unsafe extern "C" fn salty_channel_disconnect_rx_free(
    ptr: *const salty_channel_disconnect_rx_t,
) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut oneshot::Receiver<CloseCode>);
}


// *** CONNECTION *** //

/// Connect to the specified SaltyRTC server, do the server and peer handshake
/// and run the task loop.
///
/// This is a blocking call. It will end once the connection has been terminated.
/// You should probably run this in a separate thread.
///
/// Parameters:
///     host (`*c_char`, null terminated, borrowed):
///         Null terminated UTF-8 encoded C string containing the SaltyRTC server hostname.
///     port (`*uint16_t`, copied):
///         SaltyRTC server port.
///     client (`*salty_client_t`, borrowed):
///         Pointer to a `salty_client_t` instance.
///     event_loop (`*salty_event_loop_t`, borrowed):
///         The event loop that is also associated with the task.
///     sender_rx (`*salty_channel_sender_rx_t`, moved):
///         The receiving end of the channel for outgoing messages.
///         This object is returned when creating a client instance.
///     disconnect_rx (`*salty_channel_disconnect_rx_t`, moved):
///         The receiving end of the channel for closing the connection.
///         This object is returned when creating a client instance.
///     timeout_s (`uint16_t`, copied):
///         Connection and handshake timeout in seconds. Set value to `0` for no timeout.
///     ca_cert (`*uint8_t` or `NULL`, borrowed):
///         Optional pointer to bytes of a DER encoded CA certificate.
///         When no certificate is set, the OS trust chain is used.
///     ca_cert_len (`uint32_t`, copied):
///         When the `ca_cert` argument is not `NULL`, then this must be
///         set to the number of certificate bytes. Otherwise, set it to 0.
#[no_mangle]
pub unsafe extern "C" fn salty_client_connect(
    host: *const c_char,
    port: uint16_t,
    client: *const salty_client_t,
    event_loop: *const salty_event_loop_t,
    sender_rx: *const salty_channel_sender_rx_t,
    disconnect_rx: *const salty_channel_disconnect_rx_t,
    timeout_s: uint16_t,
    ca_cert: *const uint8_t,
    ca_cert_len: uint32_t,
) -> salty_client_connect_success_t {
    trace!("salty_client_connect: Initializing");

    // Null pointer checks
    if host.is_null() {
        error!("Hostname pointer is null");
        return salty_client_connect_success_t::CONNECT_NULL_ARGUMENT;
    }
    if client.is_null() {
        error!("Client pointer is null");
        return salty_client_connect_success_t::CONNECT_NULL_ARGUMENT;
    }
    if event_loop.is_null() {
        error!("Event loop pointer is null");
        return salty_client_connect_success_t::CONNECT_NULL_ARGUMENT;
    }
    if sender_rx.is_null() {
        error!("Sender RX channel pointer is null");
        return salty_client_connect_success_t::CONNECT_NULL_ARGUMENT;
    }
    if disconnect_rx.is_null() {
        error!("Disconnect RX channel pointer is null");
        return salty_client_connect_success_t::CONNECT_NULL_ARGUMENT;
    }

    // Get host string
    let hostname = match CStr::from_ptr(host).to_str() {
        Ok(host) => host,
        Err(_) => {
            error!("host argument is not valid UTF-8");
            return salty_client_connect_success_t::CONNECT_INVALID_HOST;
        },
    };

    // Recreate client RC
    let client_rc: Rc<RefCell<SaltyClient>> = Rc::from_raw(client as *const RefCell<SaltyClient>);

    // Clone RC so that the client instance can be reused
    let client_rc_clone1 = client_rc.clone();
    let client_rc_clone2 = client_rc.clone();
    let client_rc_clone3 = client_rc.clone();
    mem::forget(client_rc);

    // Get event loop reference
    let core = &mut *(event_loop as *mut Core) as &mut Core;

    // Get channel sender instances
    let sender_rx_box = Box::from_raw(sender_rx as *mut mpsc::UnboundedReceiver<Value>);
    let disconnect_rx_box = Box::from_raw(disconnect_rx as *mut oneshot::Receiver<CloseCode>);

    // Read CA certificate (if present)
    let ca_cert_opt: Option<Certificate> = if ca_cert.is_null() {
        debug!("Using system CA chain");
        None
    } else {
        debug!("Reading CA certificate");
        let bytes: &[u8] = slice::from_raw_parts(ca_cert, ca_cert_len as usize);
        Some(match Certificate::from_der(bytes) {
            Ok(cert) => cert,
            Err(e) => {
                error!("Could not parse DER encoded CA certificate: {}", e);
                return salty_client_connect_success_t::CONNECT_CERTIFICATE_ERROR;
            }
        })
    };

    // Create TlsConnector
    macro_rules! unwrap_or_tls_error {
        ($obj:expr, $errmsg:expr) => {{
            match $obj {
                Ok(val) => val,
                Err(e) => {
                    error!($errmsg, e);
                    return salty_client_connect_success_t::CONNECT_TLS_ERROR;
                }
            }
        }}
    }
    let supported_protocols = [Protocol::Tlsv12, Protocol::Tlsv11, Protocol::Tlsv10];
    let mut tls_builder = unwrap_or_tls_error!(TlsConnector::builder(),
        "Could not create TlsConnectorBuilder: {}");
    unwrap_or_tls_error!(tls_builder.supported_protocols(&supported_protocols),
        "Could not set supported TLS protocols: {}");
    if let Some(cert) = ca_cert_opt {
        unwrap_or_tls_error!(tls_builder.add_root_certificate(cert),
            "Could not add CA certificate to TlsConnectorBuilder: {}");
    }
    let tls_connector = unwrap_or_tls_error!(tls_builder.build(),
        "Could not create TlsConnector: {}");

    // Create connect future
    let connect_future = match saltyrtc_client::connect(
        hostname,
        port,
        Some(tls_connector),
        &core.handle(),
        client_rc_clone1,
    ) {
        Ok(future) => future,
        Err(e) => {
            error!("Could not create connect future: {}", e);
            return salty_client_connect_success_t::CONNECT_ERROR;
        },
    };

    // Create handshake future
    // After connecting to server, do handshake
    let timeout = match timeout_s {
        0 => None,
        seconds => Some(Duration::from_secs(seconds as u64)),
    };
    let handshake_future = connect_future
        .and_then(|ws_client| saltyrtc_client::do_handshake(ws_client, client_rc_clone2, timeout));

    // Run handshake future to completion
    let ws_client = match core.run(handshake_future) {
        Ok(ws_client) => {
            info!("Handshake done");
            ws_client
        },
        Err(e) => {
            error!("Connection error: {}", e);
            return salty_client_connect_success_t::CONNECT_ERROR;
        },
    };

    // Create task loop future
    let (task, task_loop, event_rx) = match saltyrtc_client::task_loop(ws_client, client_rc_clone3) {
        Ok(val) => val,
        Err(e) => {
            error!("Could not start task loop: {}", e);
            return salty_client_connect_success_t::CONNECT_ERROR;
        },
    };

    // Get access to task tx channel
    let task_sender: mpsc::UnboundedSender<Value> = {
        // Lock task mutex
        let mut task_locked = match task.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("Could not lock task mutex: {}", e);
                return salty_client_connect_success_t::CONNECT_ERROR;
            }
        };

        // Downcast generic Task to a RelayedDataTask
        let rdt: &mut RelayedDataTask = {
            let downcast_res = (&mut **task_locked as &mut Task)
                .downcast_mut::<RelayedDataTask>();
            match downcast_res {
                Some(task) => task,
                None => {
                    error!("Could not downcast task instance");
                    return salty_client_connect_success_t::CONNECT_ERROR;
                }
            }
        };

        match rdt.get_sender() {
            Ok(sender) => sender,
            Err(e) => {
                error!("Could not get task sender: {}", e);
                return salty_client_connect_success_t::CONNECT_ERROR;
            }
        }
    };

    // Forward outgoing messages to task
    let send_loop = (*sender_rx_box).forward(
        task_sender.sink_map_err(|e| error!("Could not sink message: {}", e))
    );

    // Run task loop future to completion
    let connection = connection::new(*disconnect_rx_box, send_loop, task_loop);
    match core.run(connection) {
        // Disconnect requested
        Ok(Either3::A(_)) => {
            // TODO
            salty_client_connect_success_t::CONNECT_OK
        },

        // All OK
        Ok(Either3::B(_)) |
        Ok(Either3::C(_)) => {
            info!("Connection ended (closed by ");
            salty_client_connect_success_t::CONNECT_OK
        }

        Err(Either3::A(e)) => {
            error!("Disconnect receiver error: {}", e);
            salty_client_connect_success_t::CONNECT_ERROR
        },

        Err(Either3::B(_)) => {
            error!("Send loop error");
            salty_client_connect_success_t::CONNECT_ERROR
        },

        Err(Either3::C(e)) => {
            error!("Task loop error: {}", e);
            salty_client_connect_success_t::CONNECT_ERROR
        },
    }
}

/// Send a message through the outgoing channel.
///
/// Parameters:
///     sender_tx (`*salty_channel_sender_tx_t`, borrowed):
///         The sending end of the channel for outgoing messages.
///     msg (`*uint8_t`, borrowed):
///         Pointer to the message bytes.
///     msg_len (`uint32_t`, copied):
///         Length of the message in bytes.
#[no_mangle]
pub unsafe extern "C" fn salty_client_send_bytes(
    sender_tx: *const salty_channel_sender_tx_t,
    msg: *const uint8_t,
    msg_len: uint32_t,
) -> salty_client_send_success_t {

    // Null pointer checks
    if sender_tx.is_null() {
        error!("Sender channel pointer is null");
        return salty_client_send_success_t::SEND_NULL_ARGUMENT;
    }
    if msg.is_null() {
        error!("Message pointer is null");
        return salty_client_send_success_t::SEND_NULL_ARGUMENT;
    }

    // Get pointer to UnboundedSender
    let sender = &*(sender_tx as *const mpsc::UnboundedSender<Value>) as &mpsc::UnboundedSender<Value>;

    // Parse message bytes into a rmpv `Value`
    let msg_slice: &[u8] = slice::from_raw_parts(msg, msg_len as usize);
    let mut msg_reader = BufReader::with_capacity(msg_slice.len(), msg_slice);
    let msg: Value = match read_value(&mut msg_reader) {
        Ok(val) => val,
        Err(e) => {
            error!("Could not send bytes: Not valid MsgPack data: {}", e);
            return salty_client_send_success_t::SEND_MESSAGE_ERROR;
        }
    };

    // Make sure that the buffer was fully consumed
    if msg_reader.bytes().next().is_some() {
        error!("Could not send bytes: Not valid msgpack data (buffer not fully consumed)");
        return salty_client_send_success_t::SEND_MESSAGE_ERROR;
    }

    match sender.unbounded_send(msg) {
        Ok(_) => salty_client_send_success_t::SEND_OK,
        Err(e) => {
            error!("Sending message failed: {}", e);
            salty_client_send_success_t::SEND_ERROR
        },
    }
}

/// Receive an event from the outgoing channel.
///
/// Parameters:
///     receiver_rx (`*salty_channel_receiver_rx_t`, borrowed):
///         The receiving end of the channel for incoming events.
///     timeout_ms (`*uint32_t`, borrowed):
///         - If this is `null`, then the function call will block.
///         - If this is `0`, then the function will never block. It will either return an event
///         or `RECV_NO_DATA`.
///         - If this is a value > 0, then the specified timeout in milliseconds will be used.
///         Either an event or `RECV_NO_DATA` (in the case of a timeout) will be returned.
#[no_mangle]
pub unsafe extern "C" fn salty_client_recv_event(
    receiver_rx: *const salty_channel_receiver_rx_t,
    timeout_ms: *const uint32_t,
) -> salty_client_recv_ret_t {
    // Null checks
    if receiver_rx.is_null() {
        error!("Receiver channel pointer is null");
        return make_event_recv_error(salty_client_recv_success_t::RECV_NULL_ARGUMENT);
    }

    enum BlockingMode {
        BLOCKING,
        NONBLOCKING,
        TIMEOUT(Duration),
    }

    // Determine blocking mode
    let blocking: BlockingMode = if timeout_ms == ptr::null() {
        BlockingMode::BLOCKING
    } else if *timeout_ms == 0 {
        BlockingMode::NONBLOCKING
    } else {
        BlockingMode::TIMEOUT(Duration::from_millis(*timeout_ms as u64))
    };

    // Get channel receiver reference
    let rx = &mut *(receiver_rx as *mut mpsc::UnboundedReceiver<Message>)
          as &mut mpsc::UnboundedReceiver<Message>;

    // Helper function
    fn make_message_event_ret(msg: Message) -> salty_client_recv_ret_t {
        match msg {
            Message::Data(val) => {
                // Encode msgpack bytes
                let bytes: Vec<u8> = match rmps::to_vec_named(&val) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("Could not encode value: {}", e);
                        return make_event_recv_error(salty_client_recv_success_t::RECV_ERROR);
                    }
                };

                // Get pointer to bytes on heap
                let bytes_box = bytes.into_boxed_slice();
                let bytes_len = bytes_box.len();
                let bytes_ptr = Box::into_raw(bytes_box);

                // Make event struct
                let event = salty_event_t {
                    event_type: salty_event_type_t::EVENT_INCOMING_MSG,
                    msg_bytes: bytes_ptr as *const uint8_t,
                    msg_bytes_len: bytes_len,
                    close_code: 0,
                };

                // Get pointer to event on heap
                let event_ptr = Box::into_raw(Box::new(event));

                // TODO: Add function to free allocated memory.

                salty_client_recv_ret_t {
                    success: salty_client_recv_success_t::RECV_OK,
                    event: event_ptr,
                }
            },
            Message::Disconnect(close_code) => {
                // Make event struct
                let event = salty_event_t {
                    event_type: salty_event_type_t::EVENT_DISCONNECTED,
                    msg_bytes: ptr::null(),
                    msg_bytes_len: 0,
                    close_code: close_code.as_number(),
                };

                // Get pointer to event on heap
                let event_ptr = Box::into_raw(Box::new(event));

                // TODO: Add function to free allocated memory.

                salty_client_recv_ret_t {
                    success: salty_client_recv_success_t::RECV_OK,
                    event: event_ptr,
                }
            },
        }
    }

    match blocking {
        BlockingMode::BLOCKING => {
            match rx.wait().next() {
                Some(Ok(msg)) => make_message_event_ret(msg),
                None => make_event_recv_error(salty_client_recv_success_t::RECV_STREAM_ENDED),
                Some(Err(_)) => {
                    error!("Could not receive event");
                    make_event_recv_error(salty_client_recv_success_t::RECV_ERROR)
                },
            }
        }
        BlockingMode::NONBLOCKING => {
            let mut rx_future = rx.into_future();
            let nb_future = nonblocking::new(&mut rx_future);
            let res = nb_future.wait();
            match res {
                Ok(Some((Some(msg), _))) => make_message_event_ret(msg),
                Ok(Some((None, _))) => make_event_recv_error(salty_client_recv_success_t::RECV_STREAM_ENDED),
                Ok(None) => make_event_recv_error(salty_client_recv_success_t::RECV_NO_DATA),
                Err(_) => {
                    error!("Could not receive event");
                    make_event_recv_error(salty_client_recv_success_t::RECV_ERROR)
                },
            }
        }
        BlockingMode::TIMEOUT(duration) => {
            let timeout_future = Timer::default().sleep(duration).map_err(|_| ());
            let rx_future = rx.into_future();
            let res = rx_future.select2(timeout_future).wait();
            match res {
                Ok(Either::A(((Some(msg), _), _))) => make_message_event_ret(msg),
                Ok(Either::A(((None, _), _))) => make_event_recv_error(salty_client_recv_success_t::RECV_STREAM_ENDED),
                Ok(Either::B(_)) => make_event_recv_error(salty_client_recv_success_t::RECV_NO_DATA),
                Err(_) => {
                    error!("Could not receive event");
                    make_event_recv_error(salty_client_recv_success_t::RECV_ERROR)
                },
            }
        }
    }
}

/// Free an event loop instance.
#[no_mangle]
pub unsafe extern "C" fn salty_client_recv_ret_free(recv_ret: salty_client_recv_ret_t) {
    if recv_ret.event.is_null() {
        debug!("salty_client_event_free: Event is already null");
        return;
    }
    let event = Box::from_raw(recv_ret.event as *mut salty_event_t);
    if !event.msg_bytes.is_null() {
        Vec::from_raw_parts(
            event.msg_bytes as *mut u8,
            event.msg_bytes_len,
            event.msg_bytes_len,
        );
    }
}


/// Close the connection.
///
/// Depending on whether this succeeds or not, the `disconnect_tx` instance is
/// freed or not:
///
/// - DISCONNECT_OK: The `disconnect_tx` instance was freed
/// - DISCONNECT_NULL_ARGUMENT: The `disconnect_tx` instance was not freed
/// - DISCONNECT_BAD_CLOSE_CODE: The `disconnect_tx` instance was not freed
/// - DISCONNECT_ERROR: The `disconnect_tx` instance was freed
///
/// Parameters:
///     disconnect_tx (`*salty_channel_disconnect_tx_t`, borrowed or moved):
///         The sending end of the channel for closing the connection.
///         This object is returned when creating a client instance.
///     close_code (`uint16_t`, copied):
///         The close code according to the SaltyRTC protocol specification.
#[no_mangle]
pub unsafe extern "C" fn salty_client_disconnect(
    disconnect_tx: *const salty_channel_disconnect_tx_t,
    close_code: uint16_t, // TODO: Enum
) -> salty_client_disconnect_success_t {
    // Null pointer checks
    if disconnect_tx.is_null() {
        error!("Disconnect pointer is null");
        return salty_client_disconnect_success_t::DISCONNECT_NULL_ARGUMENT;
    }

    let disconnect_tx_box = Box::from_raw(disconnect_tx as *mut oneshot::Sender<CloseCode>);
    let code = match CloseCode::from_number(close_code) {
        Some(code) => code,
        None => {
            // Forget about sender, to prevent freeing the memory.
            mem::forget(disconnect_tx_box);
            return salty_client_disconnect_success_t::DISCONNECT_BAD_CLOSE_CODE;
        }
    };
    match (*disconnect_tx_box).send(code) {
        Ok(_) => salty_client_disconnect_success_t::DISCONNECT_OK,
        Err(_) => {
            error!("Could not close connection");
            salty_client_disconnect_success_t::DISCONNECT_ERROR
        }
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use saltyrtc_client_ffi::{salty_keypair_new, salty_event_loop_new, salty_event_loop_get_remote};

    #[test]
    fn test_send_bytes_sender_null_ptr() {
        let msg = Box::into_raw(Box::new(vec![1, 2, 3])) as *const uint8_t;
        let result = unsafe {
            salty_client_send_bytes(
                ptr::null(),
                msg,
                3,
            )
        };
        assert_eq!(result, salty_client_send_success_t::SEND_NULL_ARGUMENT);
    }

    #[test]
    fn test_send_bytes_msg_null_ptr() {
        let (tx, _rx) = mpsc::unbounded::<Value>();
        let tx_ptr = Box::into_raw(Box::new(tx)) as *const salty_channel_sender_tx_t;
        let result = unsafe {
            salty_client_send_bytes(
                tx_ptr,
                ptr::null(),
                3,
            )
        };
        assert_eq!(result, salty_client_send_success_t::SEND_NULL_ARGUMENT);
    }

    #[test]
    fn test_msgpack_decode_invalid() {
        // Create channel
        let (tx, _rx) = mpsc::unbounded::<Value>();
        let tx_ptr = Box::into_raw(Box::new(tx)) as *const salty_channel_sender_tx_t;

        // Create message
        // This will result in a msgpack value `Integer(1)`, the remaining two integers
        // are not part of the message anymore.
        let msg_ptr = Box::into_raw(Box::new(vec![1, 2, 3])) as *const uint8_t;

        let result = unsafe {
            salty_client_send_bytes(
                tx_ptr,
                msg_ptr,
                3,
            )
        };
        assert_eq!(result, salty_client_send_success_t::SEND_MESSAGE_ERROR);
    }

    #[test]
    fn test_recv_rx_channel_null_ptr() {
        let result = unsafe { salty_client_recv_event(ptr::null(), ptr::null()) };
        assert_eq!(result.success, salty_client_recv_success_t::RECV_NULL_ARGUMENT);
    }

    #[test]
    fn test_recv_nonblocking() {
        let (tx, rx) = mpsc::unbounded::<Message>();
        let rx_ptr = Box::into_raw(Box::new(rx)) as *const salty_channel_receiver_rx_t;

        let timeout_ptr = Box::into_raw(Box::new(0u32)) as *const uint32_t;

        // Receive no data
        let result = unsafe { salty_client_recv_event(rx_ptr, timeout_ptr) };
        assert_eq!(result.success, salty_client_recv_success_t::RECV_NO_DATA);

        // Send two messages
        tx.unbounded_send(Message::Data(Value::Integer(42.into()))).unwrap();
        tx.unbounded_send(Message::Disconnect(CloseCode::from_number(3002).unwrap())).unwrap();

        // Receive data
        let result = unsafe { salty_client_recv_event(rx_ptr, timeout_ptr) };
        assert_eq!(result.success, salty_client_recv_success_t::RECV_OK);
        assert_eq!(result.event.is_null(), false);
        unsafe {
            let event = &*result.event;
            assert_eq!(event.event_type, salty_event_type_t::EVENT_INCOMING_MSG);
            assert_eq!(event.msg_bytes_len, 1);
            let msg_bytes = Vec::from_raw_parts(
                event.msg_bytes as *mut u8,
                event.msg_bytes_len,
                event.msg_bytes_len,
            );
            assert_eq!(msg_bytes, vec![42]);
            assert_eq!(event.close_code, 0);
        }

        // Receive disconnect
        let result = unsafe { salty_client_recv_event(rx_ptr, timeout_ptr) };
        assert_eq!(result.success, salty_client_recv_success_t::RECV_OK);
        assert_eq!(result.event.is_null(), false);
        unsafe {
            let event = &*result.event;
            assert_eq!(event.event_type, salty_event_type_t::EVENT_DISCONNECTED);
            assert_eq!(event.close_code, 3002);
            assert!(event.msg_bytes.is_null());
            assert_eq!(event.msg_bytes_len, 0);
        }

        // Receive no data
        let result = unsafe { salty_client_recv_event(rx_ptr, timeout_ptr) };
        assert_eq!(result.success, salty_client_recv_success_t::RECV_NO_DATA);

        // Drop sender
        ::std::mem::drop(tx);

        // Receive stream ended
        let result = unsafe { salty_client_recv_event(rx_ptr, timeout_ptr) };
        assert_eq!(result.success, salty_client_recv_success_t::RECV_STREAM_ENDED);

        // Free some memory
        unsafe {
            Box::from_raw(timeout_ptr as *mut u32);
            Box::from_raw(rx_ptr as *mut salty_channel_receiver_rx_t);
        }
    }

    #[test]
    fn test_recv_timeout_thread() {
        let (tx, rx) = mpsc::unbounded::<Message>();
        let rx_ptr = Box::into_raw(Box::new(rx)) as *const salty_channel_receiver_rx_t;

        let timeout_1s_ptr = Box::into_raw(Box::new(1_000u32)) as *const uint32_t;
        let timeout_600s_ptr = Box::into_raw(Box::new(600_000u32)) as *const uint32_t;

        // Set up thread to post a message after 1.5 seconds
        let child = ::std::thread::spawn(move || {
            ::std::thread::sleep(Duration::from_millis(1500));
            tx.unbounded_send(Message::Disconnect(CloseCode::from_number(3000).unwrap())).unwrap();
        });

        // Wait for max 1s, but receive no data (timeout)
        let result = unsafe { salty_client_recv_event(rx_ptr, timeout_1s_ptr) };
        assert_eq!(result.success, salty_client_recv_success_t::RECV_NO_DATA);

        // Wait again for max 1s, now data from the thread should arrive!
        let result = unsafe { salty_client_recv_event(rx_ptr, timeout_1s_ptr) };
        assert_eq!(result.success, salty_client_recv_success_t::RECV_OK);
        assert_eq!(result.event.is_null(), false);
        unsafe {
            let event = &*result.event;
            assert_eq!(event.event_type, salty_event_type_t::EVENT_DISCONNECTED);
            assert_eq!(event.close_code, 3000);
            assert!(event.msg_bytes.is_null());
            assert_eq!(event.msg_bytes_len, 0);
        }

        // Join thread. This will result in a dropped sender.
        child.join().unwrap();

        // Immediately receive stream ended
        let result = unsafe { salty_client_recv_event(rx_ptr, timeout_600s_ptr) };
        assert_eq!(result.success, salty_client_recv_success_t::RECV_STREAM_ENDED);

        // Free some memory
        unsafe {
            Box::from_raw(timeout_1s_ptr as *mut u32);
            Box::from_raw(timeout_600s_ptr as *mut u32);
            Box::from_raw(rx_ptr as *mut salty_channel_receiver_rx_t);
        }
    }

    #[test]
    fn test_recv_timeout_simple() {
        let (_tx, rx) = mpsc::unbounded::<Message>();
        let rx_ptr = Box::into_raw(Box::new(rx)) as *const salty_channel_receiver_rx_t;

        // Wait for max 500ms, but receive no data (timeout)
        let timeout_500ms_ptr = Box::into_raw(Box::new(500u32)) as *const uint32_t;
        let result = unsafe { salty_client_recv_event(rx_ptr, timeout_500ms_ptr) };
        assert_eq!(result.success, salty_client_recv_success_t::RECV_NO_DATA);

        // Free some memory
        unsafe {
            Box::from_raw(timeout_500ms_ptr as *mut u32);
            Box::from_raw(rx_ptr as *mut salty_channel_receiver_rx_t);
        }
    }

    #[test]
    fn test_free_channels() {
        let keypair = salty_keypair_new();
        let event_loop = salty_event_loop_new();
        let remote = unsafe { salty_event_loop_get_remote(event_loop) };
        let client_ret = unsafe { salty_relayed_data_initiator_new(keypair, remote, 0, ptr::null()) };
        unsafe {
            salty_channel_receiver_rx_free(client_ret.receiver_rx);
            salty_channel_sender_tx_free(client_ret.sender_tx);
            salty_channel_sender_rx_free(client_ret.sender_rx);
        }
    }

    /// Using zero bytes as trusted key should fail.
    #[test]
    fn test_initiator_trusted_key_validation() {
        let keypair = salty_keypair_new();
        let event_loop = salty_event_loop_new();
        let remote = unsafe { salty_event_loop_get_remote(event_loop) };
        let zero_bytes = [0; 32];
        let zero_bytes_ptr = Box::into_raw(Box::new(zero_bytes)) as *const uint8_t;
        let client_ret = unsafe { salty_relayed_data_initiator_new(keypair, remote, 0, zero_bytes_ptr) };
        assert_eq!(client_ret.success, salty_relayed_data_success_t::TRUSTED_KEY_INVALID);
    }

    /// Using zero bytes as public key should fail.
    #[test]
    fn test_responder_public_key_validation() {
        let keypair = salty_keypair_new();
        let event_loop = salty_event_loop_new();
        let remote = unsafe { salty_event_loop_get_remote(event_loop) };
        let nonzero_bytes = [1; 32];
        let nonzero_bytes_ptr = Box::into_raw(Box::new(nonzero_bytes)) as *const uint8_t;
        let zero_bytes = [0; 32];
        let zero_bytes_ptr = Box::into_raw(Box::new(zero_bytes)) as *const uint8_t;
        let client_ret = unsafe { salty_relayed_data_responder_new(keypair, remote, 0, zero_bytes_ptr, nonzero_bytes_ptr) };
        assert_eq!(client_ret.success, salty_relayed_data_success_t::PUBKEY_INVALID);
    }

    /// Using zero bytes as auth token should fail.
    #[test]
    fn test_responder_auth_token_validation() {
        let keypair = salty_keypair_new();
        let event_loop = salty_event_loop_new();
        let remote = unsafe { salty_event_loop_get_remote(event_loop) };
        let nonzero_bytes = [1; 32];
        let nonzero_bytes_ptr = Box::into_raw(Box::new(nonzero_bytes)) as *const uint8_t;
        let zero_bytes = [0; 32];
        let zero_bytes_ptr = Box::into_raw(Box::new(zero_bytes)) as *const uint8_t;
        let client_ret = unsafe { salty_relayed_data_responder_new(keypair, remote, 0, nonzero_bytes_ptr, zero_bytes_ptr) };
        assert_eq!(client_ret.success, salty_relayed_data_success_t::AUTH_TOKEN_INVALID);
    }

}
