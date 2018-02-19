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
extern crate saltyrtc_client;
extern crate saltyrtc_task_relayed_data;
extern crate tokio_core;

mod constants;
pub mod saltyrtc_client_ffi;

use std::cell::RefCell;
use std::ffi::CStr;
use std::io::{BufReader, Read};
use std::mem;
use std::ptr;
use std::rc::Rc;
use std::slice;
use std::time::Duration;

use libc::{uint8_t, uint16_t, uint32_t, c_char};
use saltyrtc_client::{SaltyClient, SaltyClientBuilder};
use saltyrtc_client::crypto::{KeyPair, PublicKey, AuthToken};
use saltyrtc_client::dep::futures::{Future, Stream, Sink};
use saltyrtc_client::dep::futures::future::Either;
use saltyrtc_client::dep::futures::sync::mpsc;
use saltyrtc_client::dep::native_tls::{TlsConnector, Protocol, Certificate};
use saltyrtc_client::dep::rmpv::Value;
use saltyrtc_client::dep::rmpv::decode::read_value;
use saltyrtc_client::tasks::{BoxedTask, Task};
pub use saltyrtc_client_ffi::{salty_client_t, salty_keypair_t, salty_remote_t, salty_event_loop_t};
use saltyrtc_task_relayed_data::{RelayedDataTask, Message};
use tokio_core::reactor::{Core, Remote};

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
}

/// The channel for receiving incoming messages.
///
/// On the Rust side, this is an `UnboundedReceiver<Message>`.
#[no_mangle]
pub enum salty_channel_receiver_rx_t {}

/// The channel for sending outgoing messages (sending end).
///
/// On the Rust side, this is an `UnboundedSender<Value>`.
#[no_mangle]
pub enum salty_channel_sender_tx_t {}

/// The channel for sending outgoing messages (receiving end).
///
/// On the Rust side, this is an `UnboundedReceiver<Value>`.
#[no_mangle]
pub enum salty_channel_sender_rx_t {}

/// Result type with all potential error codes.
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


// *** HELPER FUNCTIONS *** //

/// Helper function to return error values.
fn make_error(reason: salty_relayed_data_success_t) -> salty_relayed_data_client_ret_t {
    salty_relayed_data_client_ret_t {
        success: reason,
        client: ptr::null(),
        receiver_rx: ptr::null(),
        sender_tx: ptr::null(),
        sender_rx: ptr::null(),
    }
}

struct ClientBuilderRet {
    builder: SaltyClientBuilder,
    receiver_rx: mpsc::UnboundedReceiver<Message>,
    sender_tx: mpsc::UnboundedSender<Value>,
    sender_rx: mpsc::UnboundedReceiver<Value>,
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

    // Instantiate task
    let task = RelayedDataTask::new(*remote, receiver_tx);

    // Determine ping interval
    let interval = match ping_interval_seconds {
        0 => None,
        secs => Some(Duration::from_secs(secs as u64))
    };

    // Create builder instance
    let builder = SaltyClientBuilder::new(*keypair)
        .add_task(Box::new(task) as BoxedTask)
        .with_ping_interval(interval);

    Ok(ClientBuilderRet {
        builder,
        receiver_rx,
        sender_tx,
        sender_rx,
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
/// Returns:
///     A `salty_relayed_data_client_ret_t` struct.
#[no_mangle]
pub unsafe extern "C" fn salty_relayed_data_initiator_new(
    keypair: *const salty_keypair_t,
    remote: *const salty_remote_t,
    ping_interval_seconds: uint32_t,
) -> salty_relayed_data_client_ret_t {
    // Parse arguments and create SaltyRTC builder
    let ret = match create_client_builder(keypair, remote, ping_interval_seconds) {
        Ok(val) => val,
        Err(reason) => return make_error(reason),
    };

    // Create client instance
    let client_res = ret.builder.initiator();
    let client = match client_res {
        Ok(client) => client,
        Err(e) => {
            error!("Could not instantiate SaltyClient: {}", e);
            return make_error(salty_relayed_data_success_t::CREATE_FAILED);
        },
    };

    salty_relayed_data_client_ret_t {
        success: salty_relayed_data_success_t::OK,
        client: Rc::into_raw(Rc::new(RefCell::new(client))) as *const salty_client_t,
        receiver_rx: Box::into_raw(Box::new(ret.receiver_rx)) as *const salty_channel_receiver_rx_t,
        sender_tx: Box::into_raw(Box::new(ret.sender_tx)) as *const salty_channel_sender_tx_t,
        sender_rx: Box::into_raw(Box::new(ret.sender_rx)) as *const salty_channel_sender_rx_t,
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
///         One-time auth token from the initiator. If set, this must be a 32 byte `uint8_t` array.
///         Set this to `null` when restoring a trusted session.
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
        Err(reason) => return make_error(reason),
    };

    // Get public key slice
    if initiator_pubkey.is_null() {
        error!("Initiator public key is a null pointer");
        return make_error(salty_relayed_data_success_t::NULL_ARGUMENT);
    }
    let pubkey_slice: &[u8] = slice::from_raw_parts(initiator_pubkey, 32);

    // Just to rule out stupid mistakes, make sure that the public key is not all-zero
    if pubkey_slice.iter().all(|&x| x == 0) {
        error!("Public key bytes are all zero!");
        return make_error(salty_relayed_data_success_t::PUBKEY_INVALID);
    }

    // Parse public key
    let pubkey = match PublicKey::from_slice(pubkey_slice) {
        Some(pubkey) => pubkey,
        None => {
            error!("Public key bytes could not be parsed");
            return make_error(salty_relayed_data_success_t::PUBKEY_INVALID);
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
            return make_error(salty_relayed_data_success_t::AUTH_TOKEN_INVALID);
        }

        // Parse
        match AuthToken::from_slice(auth_token_slice) {
            Ok(token) => Some(token),
            Err(e) => {
                error!("Could not parse auth token bytes: {}", e);
                return make_error(salty_relayed_data_success_t::AUTH_TOKEN_INVALID);
            }
        }
    };

    // Create client instance
    let client_res = ret.builder.responder(pubkey, auth_token_opt);
    let client = match client_res {
        Ok(client) => client,
        Err(e) => {
            error!("Could not instantiate SaltyClient: {}", e);
            return make_error(salty_relayed_data_success_t::CREATE_FAILED);
        },
    };

    salty_relayed_data_client_ret_t {
        success: salty_relayed_data_success_t::OK,
        client: Rc::into_raw(Rc::new(RefCell::new(client))) as *const salty_client_t,
        receiver_rx: Box::into_raw(Box::new(ret.receiver_rx)) as *const salty_channel_receiver_rx_t,
        sender_tx: Box::into_raw(Box::new(ret.sender_tx)) as *const salty_channel_sender_tx_t,
        sender_rx: Box::into_raw(Box::new(ret.sender_rx)) as *const salty_channel_sender_rx_t,
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
        warn!("Tried to dereference a null pointer");
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
    timeout_s: uint16_t,
    ca_cert: *const uint8_t,
    ca_cert_len: uint32_t,
) -> salty_client_connect_success_t {
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
        warn!("Sender RX channel pointer is null");
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

    // Get channel sender instance
    let sender_rx_box = Box::from_raw(sender_rx as *mut mpsc::UnboundedReceiver<Value>);

    // Read CA certificate (if present)
    let ca_cert_opt: Option<Certificate> = if ca_cert.is_null() {
        None
    } else {
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
    let (task, task_loop) = match saltyrtc_client::task_loop(ws_client, client_rc_clone3) {
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
    match core.run(task_loop.select2(send_loop)) {
        // Everything OK
        Ok(_) => {
            info!("Connection ended");
            salty_client_connect_success_t::CONNECT_OK
        },

        // Task loop failed
        Err(Either::A((e, _))) => {
            error!("Task loop error: {}", e);
            salty_client_connect_success_t::CONNECT_ERROR
        },

        // Send loop failed
        Err(Either::B(_)) => {
            error!("Send loop error");
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


#[cfg(test)]
mod tests {
    use super::*;

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
}
