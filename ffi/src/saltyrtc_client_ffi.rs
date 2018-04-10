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
use std::ptr;
use std::sync::Mutex;

use libc::uint8_t;
use log::LevelFilter;
use log4rs::{Handle as LogHandle, init_config};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use saltyrtc_client::crypto::KeyPair;
use tokio_core::reactor::{Core, Remote};

use constants::*;


// *** TYPES *** //

/// A key pair.
#[no_mangle]
pub enum salty_keypair_t {}

/// An event loop instance.
///
/// The event loop is not thread safe.
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
        error!("Tried to dereference a null pointer");
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
