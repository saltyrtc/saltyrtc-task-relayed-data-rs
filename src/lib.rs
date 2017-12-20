#[macro_use] extern crate log;
extern crate saltyrtc_client;

use std::borrow::{Cow};
use std::collections::{HashMap};

use saltyrtc_client::{Task};
use saltyrtc_client::errors::{Error};
use saltyrtc_client::rmpv::{Value};


static TASK_NAME: &'static str = "v0.relayed-data.tasks.saltyrtc.org";


/// An implementation of the
/// [Relayed Data Task](https://github.com/saltyrtc/saltyrtc-meta/blob/master/Task-RelayedData.md).
///
/// This task uses the end-to-end encrypted WebSocket connection set up by
/// the SaltyRTC protocol to send user defined messages.
#[derive(Debug)]
pub struct RelayedDataTask;

impl Task for RelayedDataTask {

    /// Initialize the task with the task data from the peer, sent in the `Auth` message.
    ///
    /// The task should keep track internally whether it has been initialized or not.
    fn init(&mut self, data: &Option<HashMap<String, Value>>) -> Result<(), Error> {
        if data.is_some() {
            warn!("Task was initialized with some data, even though it should be `None`!");
        }
        Ok(())
    }

    /// Used by the signaling class to notify task that the peer handshake is over.
    ///
    /// This is the point where the task can take over.
    fn on_peer_handshake_done(&mut self) {
        info!("Relayed data task is taking over");
    }

    /// Return whether the specified message type is supported by this task.
    ///
    /// Incoming messages with accepted types will be passed to the task.
    /// Otherwise, the message is dropped.
    fn type_supported(&self, type_: &str) -> bool {
        type_ == "data"
        // TODO: application / close?
    }

    /// This method is called by SaltyRTC when a task related message
    /// arrives through the WebSocket.
    fn on_task_message(&mut self, message: Value) {
        debug!("New task message arrived: {:?}", message);
    }

    /// Send bytes through the task signaling channel.
    ///
    /// This method should only be called after the handover.
    ///
    /// Note that the data passed in to this method should *not* already be encrypted. Otherwise,
    /// data will be encrypted twice.
    fn send_signaling_message(&self, _payload: &[u8]) {
        panic!("send_signaling_message called even though task does not implement handover");
    }

    /// Return the task protocol name.
    fn name(&self) -> Cow<'static, str> {
        TASK_NAME.into()
    }

    /// Return the task data used for negotiation in the `auth` message.
    fn data(&self) -> Option<HashMap<String, Value>> {
        None
    }

    /// This method is called by the signaling class when sending and receiving 'close' messages.
    fn close(&mut self, _reason: u8) {
        // Nothing to do
    }
}
