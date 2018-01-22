#[macro_use] extern crate log;
extern crate saltyrtc_client;
extern crate tokio_core;

use std::borrow::Cow;
use std::collections::HashMap;
use std::mem;

use saltyrtc_client::{CloseCode, Task};
use saltyrtc_client::errors::Error;
use saltyrtc_client::futures::future;
use saltyrtc_client::futures::{Stream, Sink, Future};
use saltyrtc_client::futures::sync::mpsc::{Sender, Receiver};
use saltyrtc_client::futures::sync::oneshot::Sender as OneshotSender;
use saltyrtc_client::rmpv::Value;
use tokio_core::reactor::Remote;


static TASK_NAME: &'static str = "v0.relayed-data.tasks.saltyrtc.org";
const TYPE_DATA: &'static str = "data";
const KEY_TYPE: &'static str = "type";
const KEY_PAYLOAD: &'static str = "p";


/// An implementation of the
/// [Relayed Data Task](https://github.com/saltyrtc/saltyrtc-meta/blob/master/Task-RelayedData.md).
///
/// This task uses the end-to-end encrypted WebSocket connection set up by
/// the SaltyRTC protocol to send user defined messages.
#[derive(Debug)]
pub struct RelayedDataTask {
    /// A remote handle so that tasks can be enqueued in the reactor core.
    remote: Remote,

    /// The connection state, either started or stopped.
    /// The connection context is embedded in `State::Started`.
    state: State,

    /// The sending end of a channel to send incoming messages to the task user.
    incoming_tx: Sender<Message>,
}

#[derive(Debug)]
pub enum State {
    Stopped,
    Started(ConnectionContext),
}

#[derive(Debug)]
pub struct ConnectionContext {
    outgoing_tx: Sender<Value>,
    disconnect_tx: OneshotSender<Option<CloseCode>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Data(Value),
    Disconnect(CloseCode),
}

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

    /// Used by the signaling class to notify task that the peer handshake is done.
    ///
    /// This is the point where the task can take over.
    fn start(&mut self,
             outgoing_tx: Sender<Value>,
             incoming_rx: Receiver<Value>,
             disconnect_tx: OneshotSender<Option<CloseCode>>) {
        info!("Relayed data task is taking over");

        // Check for current state
        match self.state {
            State::Stopped => {
                error!("The `start` method was called in `Started` state! Ignoring.");
                return;
            },
            _ => {},
        };

        // Update state
        let cctx = ConnectionContext {
            outgoing_tx,
            disconnect_tx,
        };
        self.state = State::Started(cctx);

        // Handle incoming messages
        // TODO: Better error handling
        let incoming_tx = self.incoming_tx.clone();
        self.remote.spawn(move |handle| {
            let handle = handle.clone();
            incoming_rx.for_each(move |val: Value| {
                // Validate value type
                let map = match val {
                    Value::Map(map) => map,
                    _ => panic!("Invalid msgpack message type (not a map)"),
                };

                // Validate message type
                let msg_type = map
                    .iter()
                    .filter(|&&(ref k, _)| k.as_str() == Some(KEY_TYPE))
                    .filter_map(|&(_, ref v)| v.as_str())
                    .next()
                    .expect("Message type missing");
                if msg_type != TYPE_DATA {
                    panic!("Unknown message type: {}");
                }

                // Extract payload
                let payload_opt = map
                    .iter()
                    .filter(|&&(ref k, _)| k.as_str() == Some(KEY_PAYLOAD))
                    .map(|&(_, ref v)| v)
                    .next();
                match payload_opt {
                    Some(payload) => {
                        // Send payload through channel
                        let incoming_tx = incoming_tx.clone();
                        debug!("Sending {} message payload through channel", TYPE_DATA);
                        handle.spawn(
                            incoming_tx
                                .send(Message::Data(payload.clone()))
                                .map(|_| ()) // TODO
                                .map_err(|_| ()) // TODO
                        )
                    },
                    None => warn!("Received {} message without payload field", TYPE_DATA),
                }

                future::ok(())
            })
        });
    }

    /// Return supported message types.
    ///
    /// Incoming messages with accepted types will be passed to the task.
    /// Otherwise, the message is dropped.
    fn supported_types(&self) -> &[&'static str] {
        &[TYPE_DATA]
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
    fn on_close(&mut self, reason: CloseCode) {
        let incoming_tx = self.incoming_tx.clone();

        // Extract and destructure connection context
        let state = mem::replace(&mut self.state, State::Stopped);
        let cctx: ConnectionContext = match state {
            State::Stopped => panic!("State was already stopped!"),
            State::Started(cctx) => cctx,
        };
        let ConnectionContext { outgoing_tx: _, disconnect_tx } = cctx;

        // Notify outside about disconnecting.
        self.remote.spawn(move |_handle| {
            incoming_tx.send(Message::Disconnect(reason))
                .then(|_| {
                    // Shut down task loop
                    // TODO: Shouldn't we send along the reason?
                    let _ = disconnect_tx.send(None);
                    future::ok(())
                })
        });
    }

    /// This method can be called by the user to close the connection.
    fn close(&mut self, reason: CloseCode) {
        // Extract and destructure connection context
        let state = mem::replace(&mut self.state, State::Stopped);
        let cctx: ConnectionContext = match state {
            State::Stopped => return,
            State::Started(cctx) => cctx,
        };
        let ConnectionContext { outgoing_tx: _, disconnect_tx } = cctx;

        // Shut down task loop
        let _ = disconnect_tx.send(Some(reason));
    }
}
