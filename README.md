# DNTPD - NTP Server Implementation

[![CI/CD](https://github.com/drakon/dntpd/actions/workflows/ci.yml/badge.svg)](https://github.com/drakon/dntpd/actions)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-green.svg)](https://github.com/drakon/dntpd)
[![Standard: RFC 5905](https://img.shields.io/badge/Standard-RFC%205905-brightgreen.svg)](https://www.rfc-editor.org/rfc/rfc5905)

A production-grade NTP server implementation written in C, fully compliant with [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905). Designed for Linux with focus on security, performance, and POSIX compliance.

## Features

- **RFC 5905 Compliant** - Full NTPv4 implementation
- **Dual-stack Support** - IPv4 and IPv6 (`-4`/`-6` options)
- **Multi-threaded Architecture** - Peer and clock threads
- **Marx Filter** - Outlier rejection algorithm
- **Extension Fields** - RFC 5905 §7.5 support
- **I-DO Negotiation** - RFC 5905 §8.4 capability exchange
- **Thread-safe** - POSIX threads with proper barriers
- **systemd Integration** - Service unit included
- **GPG Signed Commits** - Verified contributions

## Quick Start

```bash
# Build
make release

# Run (requires root for port 123)
sudo ./dntpd -f

# Or with systemd
sudo cp dntpd.service /etc/systemd/system/
sudo systemctl enable --now dntpd
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-4` | Use IPv4 only |
| `-6` | Use IPv6 only |
| `-f` | Run in foreground |
| `-d` | Enable debug mode |
| `-D N` | Debug level (0-3) |
| `-c FILE` | Config file path |
| `-l FILE` | Log file path |
| `-t SEC` | Sync timeout (default: 30) |
| `-I IF` | Network interface |
| `-u USER` | Run as user |
| `-p FILE` | PID file path |

## Architecture

```
┌────────────────────────────────────────────────┐
│            DNTPD (Port 123)                     │
├────────────────────────────────────────────────┤
│  Peer Thread (RFC 5905 §5.1)                   │
│  ├── Parse NTP packets                         │
│  ├── Validate (LI, stratum, format)            │
│  └── Respond to clients                        │
├────────────────────────────────────────────────┤
│  Clock Thread (RFC 5905 §5.2)                  │
│  ├── Sync with external servers                │
│  ├── Calculate offset/delay                    │
│  └── Adjust system clock                       │
├────────────────────────────────────────────────┤
│  NTP Algorithms                                │
│  ├── Marx filter (outlier rejection)           │
│  ├── Delay/offset calculation                  │
│  └── Clock discipline                          │
└────────────────────────────────────────────────┘
```

## Building

```bash
# Release build (optimized)
make release

# Debug build (with debug symbols)
make debug

# With sanitizers
make asan    # Address sanitizer
make ubsan   # Undefined behavior sanitizer
```

## Configuration

Create `/etc/dntpd/dntpd.conf`:

```
pool.ntp.org:123
time.google.com:123
```

## Requirements

- GCC 5.0+ or Clang
- Linux kernel 3.0+
- POSIX threads
- systemd (optional)

## Security

- **CERT C** compliant code
- **Linux Kernel Style** formatting
- Signed commits (GPG)
- Static analysis (clang-tidy)
- Sanitizers in CI/CD

## Project Structure

```
dntpd/
├── main.c           # Entry point
├── config.c        # CLI/config parsing
├── socket.c       # Network sockets
├── threads.c       # Multi-threading
├── time_sync.c     # NTP sync engine
├── ntp_packet.c  # Packet parsing
├── ntp_algorithms.c  # NTP algorithms
├── filter.c       # Marx filter
├── mode_handler.c # RFC 5905 modes
├── ido.c          # I-DO negotiation
├── .github/      # CI/CD workflows
└── dntpd.8        # Man page
```

## CI/CD

GitHub Actions running:
- Build (gcc + clang)
- Static analysis (CodeQL, clang-tidy)
- Code formatting check
- Cross-compilation (ARM, i686)
- Security analysis

## License

BSD-3-Clause - See [LICENSE](LICENSE)

## Contributing

1. Fork repository
2. Create feature branch
3. Make changes (GPG signed)
4. Submit pull request

---

**Related RFCs:** [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905), [RFC 5906](https://www.rfc-editor.org/rfc/rfc5906), [RFC 8915](https://www.rfc-editor.org/rfc/rfc8915)