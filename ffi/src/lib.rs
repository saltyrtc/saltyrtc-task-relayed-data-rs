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

#[macro_use] extern crate log;
extern crate saltyrtc_client;
extern crate saltyrtc_task_relayed_data;
extern crate tokio_core;

pub mod saltyrtc_client_ffi;

use std::ptr;

use saltyrtc_client::{SaltyClient, SaltyClientBuilder};
use saltyrtc_client::crypto::KeyPair;
use saltyrtc_client::dep::futures::sync::mpsc;
use saltyrtc_client::tasks::BoxedTask;
pub use saltyrtc_client_ffi::{salty_client_t, salty_keypair_t, salty_remote_t};
use saltyrtc_task_relayed_data::{RelayedDataTask, Message};
use tokio_core::reactor::Remote;


// *** TYPES *** //

/// The channel for receiving incoming messages.
#[no_mangle]
pub enum salty_channel_receiver_t {}

#[repr(u8)]
#[no_mangle]
pub enum salty_relayed_data_success_t {
    OK = 0,
    NULL_ARGUMENT = 1,
    CREATE_FAILED = 2,
}

#[repr(C)]
#[no_mangle]
pub struct salty_relayed_data_client_ret_t {
    pub success: salty_relayed_data_success_t,
    pub client: *mut salty_client_t,
    pub rx_chan: *mut salty_channel_receiver_t,
}


// *** MAIN FUNCTIONALITY *** //

/// Initialize a new SaltyRTC client with the Relayed Data task.
///
/// Returns:
///     Either a pointer to a `salty_relayed_data_client_ret_t` struct,
///     or `null` if one of the argument pointers was null or
///     if creation of the client instance failed.
///     In the case of a failure, the error will be logged.
#[no_mangle]
pub unsafe extern "C" fn salty_relayed_data_initiator_new(
    keypair: *mut salty_keypair_t,
    remote: *mut salty_remote_t,
) -> salty_relayed_data_client_ret_t {
    // Helper function to return error values
    fn error(reason: salty_relayed_data_success_t) -> salty_relayed_data_client_ret_t {
        salty_relayed_data_client_ret_t {
            success: reason,
            client: ptr::null_mut(),
            rx_chan: ptr::null_mut(),
        }
    }

    // Null check
    if keypair.is_null() {
        error!("Keypair pointer is null");
        return error(salty_relayed_data_success_t::NULL_ARGUMENT);
    }
    if remote.is_null() {
        error!("Remote pointer is null");
        return error(salty_relayed_data_success_t::NULL_ARGUMENT);
    }

    // Recreate pointer instances
    let keypair = Box::from_raw(keypair as *mut KeyPair);
    let remote = Box::from_raw(remote as *mut Remote);

    // Create communication channels
    let (tx, rx) = mpsc::unbounded();

    // Instantiate task
    let task = RelayedDataTask::new(*remote, tx);

    // Create client instance
    let client_res = SaltyClientBuilder::new(*keypair)
        .add_task(Box::new(task) as BoxedTask)
        .initiator();
    let client = match client_res {
        Ok(client) => client,
        Err(e) => {
            error!("Could not instantiate SaltyClient: {}", e);
            return error(salty_relayed_data_success_t::CREATE_FAILED);
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
