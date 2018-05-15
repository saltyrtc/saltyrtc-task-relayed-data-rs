# SaltyRTC Relayed Data Task

[![CircleCI][circle-ci-badge]][circle-ci]
[![Join our chat on Gitter](https://badges.gitter.im/saltyrtc/Lobby.svg)](https://gitter.im/saltyrtc/Lobby)

**Note:** This library is in early development stage and does not yet work properly.


## Testing

### Unit Tests

Prerequisites:

* You need to install `valgrind` and `splint`
* The integration tests currently require a `saltyrtc.der` test CA
  certificate in the root directory of the repository.

To run the testsuite:

    cargo test

### Linting

To run clippy lints, compile the library with `--features clippy` on a nightly
compiler:

    $ cargo build --features clippy

If `nightly` is not your default compiler:

    $ rustup run nightly cargo build --features clippy

## Msgpack Debugging

If you enable the `msgpack-debugging` compile flag, you'll get direct msgpack
analysis URLs for all decoded messages in your `TRACE` level logs.

    cargo build --features 'msgpack-debugging'

You can customize that URL prefix at compile time using the `MSGPACK_DEBUG_URL`
env var. This is the default URL:

    MSGPACK_DEBUG_URL='https://msgpack.dbrgn.ch/#base64='


## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT) at your option.

### Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.


<!-- Badges -->
[circle-ci]: https://circleci.com/gh/saltyrtc/saltyrtc-task-relayed-data-rs/tree/master
[circle-ci-badge]: https://circleci.com/gh/saltyrtc/saltyrtc-task-relayed-data-rs/tree/master.svg?style=shield
