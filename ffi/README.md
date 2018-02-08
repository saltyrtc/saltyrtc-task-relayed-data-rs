## Building

To build the crate, simply run `cargo build` or `cargo build --release`.

If you want to skip the generation of the C headers, set the env variable
`SKIP_CBINDGEN=1` before building.

To build for iOS, install `cargo-lipo`, then run

    $ cargo lipo --release


## C Example

To see a C usage example, please take a look at `tests/tests.c`.


## Testing

### Rust tests

Simply run `cargo test`.

Note: The integration tests currently require a `saltyrtc.der` test CA
certificate in the root directory of the repository.

### C tests

The C tests are built using meson / ninja. They are run automatically when
calling `cargo test`.

Dependencies:

- meson
- ninja
- valgrind
- splint

If you want to build the tests manually, in the root directory, type:

    $ CFLAGS=-Werror meson build
    $ cd build
    $ ninja
