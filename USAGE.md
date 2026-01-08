# ALPINE CLI Usage (cargo run)

Use the CLI from the workspace root or the `cli/` directory. All commands go through Cargo:

```sh
cargo run -p alpine-protocol-cli -- <command> [args]
```

## Discovery
Discovery fills the local device cache used by handshake/stream commands.

```sh
cargo run -p alpine-protocol-cli -- discover
cargo run -p alpine-protocol-cli -- discover 192.168.1.50:19455
cargo run -p alpine-protocol-cli -- discover --force-unicast 192.168.1.50:19455
cargo run -p alpine-protocol-cli -- discover --local 192.168.1.10:0
```

Optional discovery flags (opt-in):

```sh
cargo run -p alpine-protocol-cli -- discover --multicast
cargo run -p alpine-protocol-cli -- discover --scan-subnets
cargo run -p alpine-protocol-cli -- discover --scan-subnets --scan-rate 200 --scan-timeout-ms 500 --scan-max-hosts 1024
```

Discovery ladder (default):
- Unicast when a target is provided.
- Broadcast on all IPv4 interfaces.
- Cached unicast fallback.
- Optional subnet scan (opt-in).

## Handshake
Handshake requires a cached device entry (run discovery first).

```sh
cargo run -p alpine-protocol-cli -- handshake --id <device_id>
cargo run -p alpine-protocol-cli -- handshake --addr 192.168.1.50:19455
cargo run -p alpine-protocol-cli -- handshake --handshake-timeout 7000
cargo run -p alpine-protocol-cli -- handshake --debug-cbor
```

## Streaming test
Requires a stored session from `handshake`.

```sh
cargo run -p alpine-protocol-cli -- stream test --id <device_id>
cargo run -p alpine-protocol-cli -- stream test --id <device_id> --ch 1=255 --ch 2=0
cargo run -p alpine-protocol-cli -- stream test --id <device_id> --interval-ms 33
cargo run -p alpine-protocol-cli -- stream test --id <device_id> --universe 1
```

## Device selectors
Most device commands accept the same selectors:

```sh
--id <device_id>
--name <model>
--manufacturer <vendor>
--addr <ip:port>
```

You can also pass a positional target: `<device_id|name|ip:port>`.

## Ping, status, identity
These currently resolve and print cached device info (no on-wire request yet).

```sh
cargo run -p alpine-protocol-cli -- ping --id <device_id>
cargo run -p alpine-protocol-cli -- status --id <device_id>
cargo run -p alpine-protocol-cli -- identity --id <device_id>
```

## Session cache

```sh
cargo run -p alpine-protocol-cli -- session list
cargo run -p alpine-protocol-cli -- session clear --id <device_id>
cargo run -p alpine-protocol-cli -- session clear --all
```

## Conformance
Runs a basic discovery + handshake validation suite.

```sh
cargo run -p alpine-protocol-cli -- conformance 192.168.1.50:19455
```

## Trust bundle

```sh
cargo run -p alpine-protocol-cli -- trust update
cargo run -p alpine-protocol-cli -- trust status
```

Environment variables (PowerShell):

```sh
$env:ALPINE_ATTESTERS_URL="http://localhost:3000/attesters/latest"
$env:ALPINE_ROOT_PUBKEY_B64="BASE64_ED25519_ROOT_PUBKEY"
```
