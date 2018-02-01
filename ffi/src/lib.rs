//! FFI bindings for the Relayed Data Task.
//!
//! The bindings currently wrap the entire SaltyRTC client API.
//! The downside of this is that only one task can be specified, not multiple.
//! That's a problem that can be solved later on.
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

extern crate libc;
#[macro_use] extern crate log;
extern crate saltyrtc_client;
extern crate saltyrtc_task_relayed_data;
extern crate tokio_core;

pub mod saltyrtc_client_ffi;

use std::ptr;
use std::slice;
use std::time::Duration;

use libc::{uint8_t, uint32_t};
use saltyrtc_client::{SaltyClient, SaltyClientBuilder};
use saltyrtc_client::crypto::{KeyPair, PublicKey, AuthToken};
use saltyrtc_client::dep::futures::sync::mpsc;
use saltyrtc_client::tasks::BoxedTask;
pub use saltyrtc_client_ffi::{salty_client_t, salty_keypair_t, salty_remote_t};
use saltyrtc_task_relayed_data::{RelayedDataTask, Message};
use tokio_core::reactor::Remote;


// *** TYPES *** //

/// The channel for receiving incoming messages.
#[no_mangle]
pub enum salty_channel_receiver_t {}

/// Result type with all potential error codes.
///
/// If no error happened, the value should be `OK` (0).
#[repr(u8)]
#[no_mangle]
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
/// Note: Before accessing `client` or `rx_chan`, make sure to check
/// the `success` field for errors. If the creation of the client
/// was not successful, then the `client` and `rx_chan` pointers will be null.
#[repr(C)]
#[no_mangle]
pub struct salty_relayed_data_client_ret_t {
    pub success: salty_relayed_data_success_t,
    pub client: *mut salty_client_t,
    pub rx_chan: *mut salty_channel_receiver_t,
}


// *** HELPER FUNCTIONS *** //

/// Helper function to return error values.
fn make_error(reason: salty_relayed_data_success_t) -> salty_relayed_data_client_ret_t {
    salty_relayed_data_client_ret_t {
        success: reason,
        client: ptr::null_mut(),
        rx_chan: ptr::null_mut(),
    }
}

/// Helper function to parse arguments and to create a new `SaltyClientBuilder`.
unsafe fn create_client_builder(
    keypair: *mut salty_keypair_t,
    remote: *mut salty_remote_t,
    ping_interval_seconds: uint32_t,
) -> Result<(SaltyClientBuilder, mpsc::UnboundedReceiver<Message>), salty_relayed_data_success_t> {
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
    let (tx, rx) = mpsc::unbounded();

    // Instantiate task
    let task = RelayedDataTask::new(*remote, tx);

    // Determine ping interval
    let interval = match ping_interval_seconds {
        0 => None,
        secs => Some(Duration::from_secs(secs as u64))
    };

    // Create builder instance
    let builder = SaltyClientBuilder::new(*keypair)
        .add_task(Box::new(task) as BoxedTask)
        .with_ping_interval(interval);

    Ok((builder, rx))
}

// *** MAIN FUNCTIONALITY *** //

/// Initialize a new SaltyRTC client as initiator with the Relayed Data task.
///
/// Arguments:
///     keypair (`*salty_keypair_t`):
///         Pointer to a key pair.
///     remote (`*salty_remote_t`):
///         Pointer to an event loop remote handle.
///     ping_interval_seconds (`uint32_t`):
///         Request that the server sends a WebSocket ping message at the specified interval.
///         Set this argument to `0` to disable ping messages.
/// Returns:
///     A `salty_relayed_data_client_ret_t` struct.
#[no_mangle]
pub unsafe extern "C" fn salty_relayed_data_initiator_new(
    keypair: *mut salty_keypair_t,
    remote: *mut salty_remote_t,
    ping_interval_seconds: uint32_t,
) -> salty_relayed_data_client_ret_t {
    // Parse arguments and create SaltyRTC builder
    let (builder, rx) = match create_client_builder(keypair, remote, ping_interval_seconds) {
        Ok(tuple) => tuple,
        Err(reason) => return make_error(reason),
    };

    // Create client instance
    let client_res = builder.initiator();
    let client = match client_res {
        Ok(client) => client,
        Err(e) => {
            error!("Could not instantiate SaltyClient: {}", e);
            return make_error(salty_relayed_data_success_t::CREATE_FAILED);
        },
    };

    salty_relayed_data_client_ret_t {
        success: salty_relayed_data_success_t::OK,
        client: Box::into_raw(Box::new(client)) as *mut salty_client_t,
        rx_chan: Box::into_raw(Box::new(rx)) as *mut salty_channel_receiver_t,
    }
}

/// Initialize a new SaltyRTC client as responder with the Relayed Data task.
///
/// Arguments:
///     keypair (`*salty_keypair_t`):
///         Pointer to a key pair.
///     remote (`*salty_remote_t`):
///         Pointer to an event loop remote handle.
///     ping_interval_seconds (`uint32_t`):
///         Request that the server sends a WebSocket ping message at the specified interval.
///         Set this argument to `0` to disable ping messages.
///     initiator_pubkey (`uint8_t[32]`):
///         Public key of the initiator. This must be a pointer to a 32 byte array.
///     auth_token (`uint8_t[32]` or `null`):
///         One-time auth token from the initiator. If set, this must be a pointer
///         to a 32 byte array. Set this to `null` when restoring a trusted session.
/// Returns:
///     A `salty_relayed_data_client_ret_t` struct.
#[no_mangle]
pub unsafe extern "C" fn salty_relayed_data_responder_new(
    keypair: *mut salty_keypair_t,
    remote: *mut salty_remote_t,
    ping_interval_seconds: uint32_t,
    initiator_pubkey: *const uint8_t,
    auth_token: *const uint8_t,
) -> salty_relayed_data_client_ret_t {
    // Parse arguments and create SaltyRTC builder
    let (builder, rx) = match create_client_builder(keypair, remote, ping_interval_seconds) {
        Ok(tuple) => tuple,
        Err(reason) => return make_error(reason),
    };

    // Get public key slice
    if initiator_pubkey.is_null() {
        error!("Initiator public key is a null pointer");
        return make_error(salty_relayed_data_success_t::NULL_ARGUMENT);
    }
    let pubkey_slice = slice::from_raw_parts(initiator_pubkey, 32);

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
        let auth_token_slice = slice::from_raw_parts(auth_token, 32);

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
    let client_res = builder.responder(pubkey, auth_token_opt);
    let client = match client_res {
        Ok(client) => client,
        Err(e) => {
            error!("Could not instantiate SaltyClient: {}", e);
            return make_error(salty_relayed_data_success_t::CREATE_FAILED);
        },
    };

    salty_relayed_data_client_ret_t {
        success: salty_relayed_data_success_t::OK,
        client: Box::into_raw(Box::new(client)) as *mut salty_client_t,
        rx_chan: Box::into_raw(Box::new(rx)) as *mut salty_channel_receiver_t,
    }
}

/// Free a SaltyRTC client with the Relayed Data task.
#[no_mangle]
pub unsafe extern "C" fn salty_relayed_data_client_free(
    ptr: *mut salty_client_t,
) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut SaltyClient);
}

/// Free a `salty_channel_receiver_t` instance.
#[no_mangle]
pub unsafe extern "C" fn salty_channel_receiver_free(
    ptr: *mut salty_channel_receiver_t,
) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut mpsc::UnboundedReceiver<Message>);
}
