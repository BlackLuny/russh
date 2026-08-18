# sunset loopback bench

Not a workspace member. Needs Rust 1.95 and a sunset checkout:

```bash
git clone --depth 1 https://github.com/mkj/sunset.git /tmp/ssh-proxy-cmp/sunset
# Cargo.toml path = /tmp/ssh-proxy-cmp/sunset
cargo +1.95.0 run --release -- --scenario session-down1ch --mib 16
```

`slow-fast` is expected to STALL: unread channels block the whole sunset session.
`direct-tcpip-reject` is expected to fail: TCP forwarding is not implemented.
