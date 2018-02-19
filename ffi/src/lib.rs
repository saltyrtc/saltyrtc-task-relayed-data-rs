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
use std::io::{BufReader, Read};
use std::mem;
use std::ptr;
use std::rc::Rc;
use std::slice;
use std::time::Duration;

use libc::{uint8_t, uint32_t};
use saltyrtc_client::{SaltyClient, SaltyClientBuilder};
use saltyrtc_client::crypto::{KeyPair, PublicKey, AuthToken};
use saltyrtc_client::dep::futures::sync::mpsc;
use saltyrtc_client::dep::rmpv::Value;
use saltyrtc_client::dep::rmpv::decode::read_value;
use saltyrtc_client::tasks::BoxedTask;
pub use saltyrtc_client_ffi::{
    salty_client_t, salty_keypair_t, salty_remote_t,
    salty_channel_receiver_rx_t, salty_channel_sender_tx_t, salty_channel_sender_rx_t,
};
use saltyrtc_task_relayed_data::{RelayedDataTask, Message};
use tokio_core::reactor::Remote;

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
