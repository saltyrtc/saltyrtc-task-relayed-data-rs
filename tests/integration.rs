//! Integration tests
//!
//! Note that these tests expect:
//!
//! * A SaltyRTC server running at `localhost:8765`
//! * The TLS certificate for that server at `saltyrtc.der` relative to the root directory

extern crate env_logger;
#[macro_use] extern crate log;
extern crate saltyrtc_client;
extern crate saltyrtc_task_relayed_data;
extern crate tokio_core;
extern crate tokio_timer;


use std::boxed::Box;
use std::cell::RefCell;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use saltyrtc_client::{WsClient, SaltyClient, SaltyClientBuilder, CloseCode, BoxedFuture};
use saltyrtc_client::crypto::{PublicKey, KeyPair, AuthToken};
use saltyrtc_client::dep::futures::{Future, Stream, Sink};
use saltyrtc_client::dep::futures::future;
use saltyrtc_client::dep::futures::sync::mpsc;
use saltyrtc_client::dep::native_tls::{Certificate, TlsConnector, Protocol};
use saltyrtc_client::dep::rmpv::Value;
use saltyrtc_client::tasks::Task;
use saltyrtc_task_relayed_data::{RelayedDataTask, Message, RelayedDataError};
use tokio_core::reactor::{Core, Remote};
use tokio_timer::Timer;


/// Wrap future in a box with type erasure.
macro_rules! boxed {
    ($future:expr) => {{
        Box::new($future) as BoxedFuture<_, _>
    }}
}


fn setup_initiator(
    keypair: KeyPair,
    remote: Remote,
) -> (SaltyClient, mpsc::UnboundedReceiver<Message>) {
    let (tx, rx) = mpsc::unbounded();
    let task = RelayedDataTask::new(remote, tx);
    let salty = SaltyClientBuilder::new(keypair)
        .add_task(Box::new(task))
        .initiator()
        .expect("Could not create initiator");
    (salty, rx)
}

fn setup_responder(
    keypair: KeyPair,
    remote: Remote,
    pubkey: PublicKey,
    auth_token: Option<AuthToken>,
) -> (SaltyClient, mpsc::UnboundedReceiver<Message>) {
    let (tx, rx) = mpsc::unbounded();
    let task = RelayedDataTask::new(remote, tx);
    let salty = SaltyClientBuilder::new(keypair)
        .add_task(Box::new(task))
        .responder(pubkey, auth_token)
        .expect("Could not create initiator");
    (salty, rx)
}

#[test]
fn integration_test() {
    // Set up logging
    env::set_var("RUST_LOG", "saltyrtc_client=debug,saltyrtc_task_relayed_data=debug,integration=trace");
    env_logger::init();

    // Tokio reactor core
    let mut core = Core::new().unwrap();

    // Read server certificate bytes
    let mut server_cert_bytes: Vec<u8> = vec![];
    File::open(&Path::new("saltyrtc.der"))
        .expect("Could not open saltyrtc.der")
        .read_to_end(&mut server_cert_bytes)
        .expect("Could not read saltyrtc.der");

    // Parse server certificate
    let server_cert = Certificate::from_der(&server_cert_bytes)
        .unwrap_or_else(|e| {
            panic!("Problem with CA cert: {}", e);
        });

    // Create TLS connector instance
    let mut tls_builder = TlsConnector::builder()
        .unwrap_or_else(|e| panic!("Could not initialize TlsConnector builder: {}", e));
    tls_builder.supported_protocols(&[Protocol::Tlsv11, Protocol::Tlsv11, Protocol::Tlsv10])
        .unwrap_or_else(|e| panic!("Could not set TLS protocols: {}", e));
    tls_builder.add_root_certificate(server_cert)
        .unwrap_or_else(|e| panic!("Could not add root certificate: {}", e));
    let tls_connector = tls_builder.build()
        .unwrap_or_else(|e| panic!("Could not initialize TlsConnector: {}", e));

    // Create keypairs
    let initiator_keypair = KeyPair::new();
    let responder_keypair = KeyPair::new();

    // The WebSocket public key
    let pubkey = initiator_keypair.public_key().clone();

    // Initialize initiator and responder
    let (initiator, rx_initiator) = setup_initiator(initiator_keypair, core.remote());
    let (responder, rx_responder) = setup_responder(responder_keypair, core.remote(), pubkey, initiator.auth_token().cloned());

    // Wrap `SaltyClient`s in `Rc<RefCell<_>>`
    let initiator = Rc::new(RefCell::new(initiator));
    let responder = Rc::new(RefCell::new(responder));

    // Futures to connect to server
    let timeout = Some(Duration::from_secs(2));
    let connect_initiator = saltyrtc_client::connect(
            "localhost",
            8765,
            Some(tls_connector.clone()),
            &core.handle(),
            initiator.clone(),
        )
        .unwrap()
        .and_then(|client| saltyrtc_client::do_handshake(client, initiator.clone(), timeout));
    let connect_responder = saltyrtc_client::connect(
            "localhost",
            8765,
            Some(tls_connector.clone()),
            &core.handle(),
            responder.clone(),
        )
        .unwrap()
        .and_then(|client| saltyrtc_client::do_handshake(client, responder.clone(), timeout));

    // Connect both clients
    let (client_initiator, client_responder): (WsClient, WsClient) = core.run(
        connect_initiator.join(connect_responder)
    ).unwrap();

    // Setup task loops
    let (task_initiator, initiator_task_loop) =
        saltyrtc_client::task_loop(client_initiator, initiator.clone()).unwrap();
    let (task_responder, responder_task_loop) =
        saltyrtc_client::task_loop(client_responder, responder.clone()).unwrap();

    let (tx_initiator, tx_responder) = {
        // Get reference to tasks and downcast them to `RelayedDataTask`.
        // We can be sure that it's a `RelayedDataTask` since that's the only one we proposed.
        let mut t_initiator = task_initiator.lock().expect("Could not lock task mutex");
        let mut t_responder = task_responder.lock().expect("Could not lock task mutex");
        let rd_task_initiator: &mut RelayedDataTask = (&mut **t_initiator as &mut Task)
            .downcast_mut::<RelayedDataTask>()
            .expect("Chosen task is not a RelayedDataTask");
        let rd_task_responder: &mut RelayedDataTask = (&mut **t_responder as &mut Task)
            .downcast_mut::<RelayedDataTask>()
            .expect("Chosen task is not a RelayedDataTask");

        // Get unbounded senders for outgoing messages
        let tx_initiator = rd_task_initiator.get_sender().unwrap();
        let tx_responder = rd_task_responder.get_sender().unwrap();
        (tx_initiator, tx_responder)
    };

    // Test scenario: After connecting, initiator sends a message to the responder.
    // The responder then replies with two messages. Once the initiator has received
    // those, it disconnects. The responder should then also disconnect, after receiving
    // the SaltyRTC 'close' message.
    let rx_loop_responder = rx_responder
        .map_err(|_| Err(RelayedDataError::Channel(("Could not read from rx_responder").into())))
        .for_each(move |msg: Message| match msg {
            Message::Data(data) => {
                // Verify incoming data
                assert_eq!(data.as_i64(), Some(1));

                // Send response
                let future = tx_responder
                    .clone()
                    .send(Value::Integer(2.into()))
                    .map(|tx| { debug!("Sent 2"); tx })
                    .and_then(|tx| tx.send(Value::Integer(3.into())))
                    .map(|tx| { debug!("Sent 3"); tx })
                    .map(|_tx| ())
                    .map_err(|e| Err(RelayedDataError::Channel(format!("Could not send message to tx_responder: {}", e))));
                boxed!(future)
            },
            Message::Disconnect(reason) => {
                assert_eq!(reason, CloseCode::WsGoingAway);
                boxed!(future::err(Ok(())))
            },
        })
        .or_else(|e| e)
        .then(|f| { debug!("† rx_loop_responder done"); f });

    let rx_loop_initiator = rx_initiator
        .map_err(|_| RelayedDataError::Channel(("Could not read from rx_initiator").into()))
        .for_each(move |msg: Message| match msg {
            Message::Data(data) => {
                // Verify incoming data
                match data.as_i64() {
                    Some(2) => { debug!("Received 2"); /* Ok, wait for 3 */ },
                    Some(3) => {
                        debug!("Received 3");
                        debug!("Done, disconnecting");
                        task_initiator.lock().unwrap().close(CloseCode::WsGoingAway);
                    },
                    _ => panic!("Received invalid value: {}", data),
                };
                future::ok(())
            },
            Message::Disconnect(_) => panic!("Initiator should disconnect first!"),
        })
        .then(|f| { debug!("† rx_loop_initiator done"); f });

    let start = tx_initiator
        .send(Value::Integer(1.into()))
        .map(|_| debug!("Sent 1"))
        .map_err(|e| RelayedDataError::Channel(e.to_string()));

    let test_future = start
        .join(initiator_task_loop.from_err())
        .join(responder_task_loop.from_err())
        .join(rx_loop_responder)
        .join(rx_loop_initiator);

    // Run futures to completion
    let timer = Timer::default();
    let timeout = timer.sleep(Duration::from_secs(3));
    match core.run(test_future.select2(timeout)) {
        Ok(_) => {},
        Err(e) => match e {
            future::Either::A((task_error, _)) => panic!("A task error occurred: {}", task_error),
            future::Either::B(_) => panic!("The test timed out"),
        },
    };
}
