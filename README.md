# ALPINE CLI

- Discovery/handshake use a single UDP socket bound to an ephemeral port chosen during handshake.
- Streaming uses a separate UDP socket bound to the same IP with port `0` (kernel-assigned) to avoid rebinding the handshake/control socket; both sockets target the same peer IP/port.
- If you need to reset handshake state, run `alpine session clear --id <device>` to drop cached sessions before re-handshaking.
- `alpine stream test` prefers a full-screen TUI (alternate screen + raw mode). If your terminal is unsupported (e.g., some JetBrains embedded terminals on WSL), the CLI will fall back to a headless text mode and tell you to use a capable terminal (Windows Terminal, native Linux terminal, iTerm2).
