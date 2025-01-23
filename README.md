# wadescan

## Prerequisites

1. up-to-date mainline kernel
2. stable rust toolchains: `rustup toolchain install stable`
3. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
4. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
5. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
6. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
7. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Usage

Add a unique index for `ip+port` and a normal index for `found_at` in the collection where server responses are stored.
Use `cargo build`, `cargo check`, etc. as normal. Run with:

```shell
# Firewall port 43169 so your OS doesn't close the connections
# Note: You probably want to use something like iptables-persistent to save this across reboots
sudo iptables -A INPUT -p tcp --dport 43169 -j DROP

cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package wadescan --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/wadescan` can be
copied to a Linux server or VM and run there.
