# SaltyRTC Relayed Data Task

[![CircleCI][circle-ci-badge]][circle-ci]
[![Join our chat on Gitter](https://badges.gitter.im/saltyrtc/Lobby.svg)](https://gitter.im/saltyrtc/Lobby)

**Note:** This library is in early development stage and does not yet work properly.


## Testing

### Unit Tests

To run the testsuite:

    cargo test

### Linting

To run clippy lints, compile the library with `--features clippy` on a nightly
compiler:

    $ cargo build --features clippy

If `nightly` is not your default compiler:

    $ rustup run nightly cargo build --features clippy


<!-- Badges -->
[circle-ci]: https://circleci.com/gh/saltyrtc/saltyrtc-task-relayed-data-rs/tree/develop
[circle-ci-badge]: https://circleci.com/gh/saltyrtc/saltyrtc-task-relayed-data-rs/tree/develop.svg?style=shield
