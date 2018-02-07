## Building

To build the crate, simply run `cargo build` or `cargo build --release`.

If you want to skip the generation of the C headers, set the env variable
`SKIP_CBINDGEN=1` before building.

## Testing

### Rust tests

Simply run `cargo test`.

### C tests

The C tests are built using meson / ninja. They are run automatically when
calling `cargo test`.

Dependencies:

- meson
- ninja
- valgrind
- splint

If you want to build the tests manually, in the root directory, type:

    $ meson build
    $ cd build
    $ ninja
