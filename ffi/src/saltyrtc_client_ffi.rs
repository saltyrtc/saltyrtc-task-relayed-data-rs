//! FFI bindings for the `saltyrtc-client` crate.
//!
//! Note: These bindings should not be used directly to build a native library,
//! instead a custom library crate should inherit from both this crate and
//! from the task FFI crate.
//!
//! That's also why only some of the types are exposed. It's not currently
//! meant as a full FFI bindings solution, it only provides some common
//! building blocks.
//!
//! While the library generates a C header file, this is primarily meant
//! for testing. FFI crates inheriting from this crate should probably
//! re-export all relevant types and generate their own header files.

use std::boxed::Box;
use std::cell::RefCell;
use std::ffi::CStr;
use std::mem;
use std::ptr;
use std::rc::Rc;
use std::slice;
use std::sync::Mutex;
use std::time::Duration;

use libc::{uint8_t, uint16_t, uint32_t, c_char};
use log::LevelFilter;
use log4rs::{Handle as LogHandle, init_config};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use saltyrtc_client::{self, SaltyClient};
use saltyrtc_client::crypto::KeyPair;
use saltyrtc_client::dep::futures::{Future, Stream};
use saltyrtc_client::dep::futures::future::Either;
use saltyrtc_client::dep::futures::sync::mpsc;
use saltyrtc_client::dep::native_tls::{TlsConnector, Protocol, Certificate};
use tokio_core::reactor::{Core, Remote};

use constants::*;


// *** TYPES *** //

/// A key pair.
#[no_mangle]
pub enum salty_keypair_t {}

/// An event loop instance.
#[no_mangle]
pub enum salty_event_loop_t {}

/// A remote handle to an event loop instance.
///
/// This type is thread safe.
#[no_mangle]
pub enum salty_remote_t {}

/// A SaltyRTC client instance.
///
/// Internally, this is a `Rc<RefCell<SaltyClient>>`.
#[no_mangle]
pub enum salty_client_t {}

/// The channel for receiving incoming messages.
///
/// On the Rust side, this is an `UnboundedReceiver<Message>`.
#[no_mangle]
pub enum salty_channel_receiver_rx_t {}

/// The channel for sending outgoing messages (sending end).
///
/// On the Rust side, this is an `UnboundedSender<Vec<u8>>`.
#[no_mangle]
pub enum salty_channel_sender_tx_t {}

/// The channel for sending outgoing messages (receiving end).
///
/// On the Rust side, this is an `UnboundedReceiver<Vec<u8>>`.
#[no_mangle]
pub enum salty_channel_sender_rx_t {}

/// Result type with all potential error codes.
///
/// If no error happened, the value should be `OK` (0).
#[repr(u8)]
#[no_mangle]
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


// *** LOGGING *** //

lazy_static! {
    static ref LOG_HANDLE: Mutex<Option<LogHandle>> = Mutex::new(None);
}

fn make_log_config(level: LevelFilter) -> Result<Config, String> {
    // Log format
    let format = "{d(%Y-%m-%dT%H:%M:%S%.3f)} [{l:<5}] {m} (({f}:{L})){n}";

    // Appender
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(format)))
        .build();

    // Create logging config object
    let config_res = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .logger(Logger::builder().build("saltyrtc_client", level))
        .logger(Logger::builder().build("saltyrtc_task_relayed_data", level))
        .logger(Logger::builder().build("saltyrtc_task_relayed_data_ffi", level))
        .build(Root::builder().appender("stdout").build(LevelFilter::Warn));

    config_res.map_err(|e| format!("Could not make log config: {}", e))
}

/// Initialize logging to stdout with log messages up to the specified log level.
///
/// Parameters:
///     level (uint8_t, copied):
///         The log level, must be in the range 0 (TRACE) to 5 (OFF).
///         See `LEVEL_*` constants for reference.
/// Returns:
///     A boolean indicating whether logging was setup successfully.
///     If setting up the logger failed, an error message will be written to stdout.
#[no_mangle]
pub extern "C" fn salty_log_init(level: uint8_t) -> bool {
    // Get access to static log handle
    let mut handle_opt = match LOG_HANDLE.lock() {
        Ok(handle_opt) => handle_opt,
        Err(e) => {
            eprintln!("salty_log_init: Could not get access to static logger mutex: {}", e);
            return false;
        }
    };
    if handle_opt.is_some() {
        eprintln!("salty_log_init: A logger is already initialized");
        return false;
    }

    // Log level
    let level_filter = match level {
        LEVEL_TRACE => LevelFilter::Trace,
        LEVEL_DEBUG => LevelFilter::Debug,
        LEVEL_INFO => LevelFilter::Info,
        LEVEL_WARN => LevelFilter::Warn,
        LEVEL_ERROR => LevelFilter::Error,
        LEVEL_OFF => LevelFilter::Off,
        _ => {
            eprintln!("salty_log_init: Invalid log level: {}", level);
            return false;
        }
    };

    // Config
    let config = match make_log_config(level_filter) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("salty_log_init: {}", e);
            return false;
        }
    };

    // Initialize logger
    let handle = match init_config(config) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("salty_log_init: Could not initialize logger: {}", e);
            return false;
        }
    };

    // Update static logger instance
    *handle_opt = Some(handle);

    // Success!
    true
}

/// Change the log level of the logger.
///
/// Parameters:
///     level (uint8_t, copied):
///         The log level, must be in the range 0 (TRACE) to 5 (OFF).
///         See `LEVEL_*` constants for reference.
/// Returns:
///     A boolean indicating whether logging was updated successfully.
///     If updating the logger failed, an error message will be written to stdout.
#[no_mangle]
pub extern "C" fn salty_log_change_level(level: uint8_t) -> bool {
    // Log level
    let level_filter = match level {
        LEVEL_TRACE => LevelFilter::Trace,
        LEVEL_DEBUG => LevelFilter::Debug,
        LEVEL_INFO => LevelFilter::Info,
        LEVEL_WARN => LevelFilter::Warn,
        LEVEL_ERROR => LevelFilter::Error,
        LEVEL_OFF => LevelFilter::Off,
        _ => {
            eprintln!("salty_log_change_level: Invalid log level: {}", level);
            return false;
        }
    };

    // Get access to static log handle
    let mut handle_opt = match LOG_HANDLE.lock() {
        Ok(opt_handle) => opt_handle,
        Err(e) => {
            eprintln!("salty_log_change_level: Could not get access to static logger mutex: {}", e);
            return false;
        }
    };
    if handle_opt.is_none() {
        eprintln!("salty_log_change_level: Logger is not initialized");
        return false;
    }

    // Config
    let config = match make_log_config(level_filter) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("salty_log_change_level: {}", e);
            return false;
        }
    };

    // Update handle
    handle_opt.as_mut().unwrap().set_config(config);

    // Success!
    true
}


// *** KEY PAIRS *** //

/// Create a new `KeyPair` instance and return an opaque pointer to it.
#[no_mangle]
pub extern "C" fn salty_keypair_new() -> *const salty_keypair_t {
    Box::into_raw(Box::new(KeyPair::new())) as *const salty_keypair_t
}

/// Get the public key from a `salty_keypair_t` instance.
///
/// Returns:
///     A null pointer if the parameter is null.
///     Pointer to a 32 byte `uint8_t` array otherwise.
#[no_mangle]
pub unsafe extern "C" fn salty_keypair_public_key(ptr: *const salty_keypair_t) -> *const uint8_t {
    if ptr.is_null() {
        warn!("Tried to dereference a null pointer");
        return ptr::null();
    }
    let keypair = &*(ptr as *const KeyPair) as &KeyPair;
    let pubkey_bytes: &[u8; 32] = &(keypair.public_key().0);
    pubkey_bytes.as_ptr()
}

/// Free a `KeyPair` instance.
///
/// Note: If you move the `salty_keypair_t` instance into a `salty_client_t` instance,
/// you do not need to free it explicitly. It is dropped when the `salty_client_t`
/// instance is freed.
#[no_mangle]
pub unsafe extern "C" fn salty_keypair_free(ptr: *const salty_keypair_t) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut KeyPair);
}


// *** EVENT LOOP *** //

/// Create a new event loop instance.
///
/// In the background, this will instantiate a Tokio reactor core.
///
/// Returns:
///     Either a pointer to the reactor core, or `null`
///     if creation of the event loop failed.
///     In the case of a failure, the error will be logged.
#[no_mangle]
pub extern "C" fn salty_event_loop_new() -> *const salty_event_loop_t {
    match Core::new() {
        Ok(reactor) => Box::into_raw(Box::new(reactor)) as *const salty_event_loop_t,
        Err(e) => {
            error!("Error: Could not create reactor core: {}", e);
            ptr::null_mut()
        }
    }
}

/// Return a remote handle from an event loop instance.
///
/// Thread safety:
///     The `salty_remote_t` instance may be used from any thread.
/// Ownership:
///     The `salty_remote_t` instance must be freed through `salty_event_loop_free_remote`,
///     or by moving it into a `salty_client_t` instance.
/// Returns:
///     A reference to the remote handle.
///     If the pointer passed in is `null`, an error is logged and `null` is returned.
#[no_mangle]
pub unsafe extern "C" fn salty_event_loop_get_remote(ptr: *const salty_event_loop_t) -> *const salty_remote_t {
    if ptr.is_null() {
        error!("Called salty_event_loop_get_remote on a null pointer");
        return ptr::null();
    }
    let core = ptr as *mut Core;
    Box::into_raw(Box::new((*core).remote())) as *const salty_remote_t
}

/// Free an event loop remote handle.
#[no_mangle]
pub unsafe extern "C" fn salty_event_loop_free_remote(ptr: *const salty_remote_t) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut Remote);
}

/// Free an event loop instance.
#[no_mangle]
pub unsafe extern "C" fn salty_event_loop_free(ptr: *const salty_event_loop_t) {
    if ptr.is_null() {
        warn!("Tried to free a null pointer");
        return;
    }
    Box::from_raw(ptr as *mut Core);
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
    let sender_rx_box = Box::from_raw(sender_rx as *mut mpsc::UnboundedReceiver<Vec<u8>>);

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

    // Create send loop future
    let send_loop = (*sender_rx_box)
        .for_each(|bytes| {
            warn!("Sending bytes: {:?}", bytes);
            Ok(())
        });

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
