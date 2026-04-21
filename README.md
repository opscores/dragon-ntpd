# DNTPD - NTP Server Implementation

[![CI](https://img.shields.io/github/actions/workflow/status/opscores/dragon-ntpd/ci.yml?label=build)](https://github.com/opscores/dragon-ntpd/actions)
[![Release](https://img.shields.io/github/v/release/opscores/dragon-ntpd)](https://github.com/opscores/dragon-ntpd/releases)
[![Last commit](https://img.shields.io/github/last-commit/opscores/dragon-ntpd/develop)](https://github.com/opscores/dragon-ntpd/commits/develop)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-green.svg)](https://github.com/opscores/dragon-ntpd)
[![Standard: RFC 5905](https://img.shields.io/badge/Standard-RFC%205905-brightgreen.svg)](https://www.rfc-editor.org/rfc/rfc5905)

A production-grade NTP server implementation written in C, fully compliant with [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905). Designed for Linux with focus on security, performance, and POSIX compliance.

## Features

- **RFC 5905 Compliant** - Full NTPv4 implementation
- **RFC 5906 Compliant** - Autokey security protocol (parsing only, HMAC-SHA1 to be added later)
- **RFC 8915 Compliant** - NTS security extensions
- **Dual-stack Support** - IPv4 and IPv6 (`-4`/`-6` options)
- **Multi-threaded Architecture** - Peer and clock threads
- **Marx Filter** - Outlier rejection algorithm
- **Extension Fields** - RFC 5905 §7.5 support
- **I-DO Negotiation** - RFC 5905 §8.4 capability exchange
- **Autokey Negotiation** - RFC 5906 Offer/Response/Key management (parsing only)
- **HMAC-SHA1 MAC** - Message authentication (to be added later)
- **Thread-safe** - POSIX threads with proper barriers
- **systemd Integration** - Service unit included
- **GPG Signed Commits** - Verified contributions

## Quick Start

```bash
# Build
make release

# Run (requires root/sudo for port 123)
sudo ./dntpd -c /etc/dntpd/dntpd.conf -f

# Or with systemd
sudo cp systemd/dntpd.service /etc/systemd/system/
sudo systemctl enable --now dntpd
```

**Config file format** (`/etc/dntpd/dntpd.conf`):

```
# One NTP server per line: ip:port
pool.ntp.org:123
time.google.com:123
```

**Modes config file** (`/etc/dntpd/modes.conf`) - Security and access policies:

```
# ACL entries
acl_allow 192.168.1.0/24 noquery,noserve
acl_allow 10.0.0.0/8 noquery,noserve

# Mode handler configuration
enable_control_messages false
enable_symmetric_mode true
enable_broadcast false
drop_unauthenticated_control true
enable_ntp_auth false
acl_default_policy noquery,noserve,limited
rate_limit_interval 2
max_response_ratio 1.0
initial_stratum 16
panic_threshold 1000
```

| Option | Description |
|--------|-------------|
| `-4` | Use IPv4 only |
| `-6` | Use IPv6 only |
| `-f, -n` | Run in foreground (no daemonize) |
| `-d` | Enable debug mode |
| `-D N, -D=N` | Debug level (0-3) |
| `-c FILE` | Config file path (default: /etc/dntpd/dntpd.conf) |
| `-l FILE` | Log file path |
| `-t SEC` | Sync timeout in seconds (1-86400, default: 30) |
| `-I IF` | Network interface |
| `-u USER` | Run as user |
| `-p FILE` | PID file path |
| `-b` | Enable broadcast mode |
| `-B ADDR` | Broadcast address |
| `-q` | Quit after first sync (testing) |

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

## Module Dependencies

### Architecture Layers

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 5: Application (main.c)                                   │
│   • Initialization, main sync loop                              │
├─────────────────────────────────────────────────────────────────┤
│ Layer 4: Business Logic (time_sync.c, ntp_algorithms.c)         │
│   • Time synchronization, peer selection algorithms             │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3: Domain Logic (ntp_packet.c, filter.c)                  │
│   • Packet parsing, MARX filter                                 │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2: Infrastructure (socket.c, threads.c)                   │
│   • Sockets, threads, TCP listener                              │
├─────────────────────────────────────────────────────────────────┤
│ Layer 1: Low-level (network4/6.c, ido.c, mode_handler.c)        │
│   • IPv4/IPv6 operations, I-DO state machine, ACL               │
└─────────────────────────────────────────────────────────────────┘
```

### Dependency Graph

```
                    ┌─────────────┐
                    │   ntpd.h    │ (Base types & constants)
                    └──────┬──────┘
           ┌───────────────┼───────────────┐
           ↓               ↓               ↓
    ┌────────────┐  ┌─────────────┐  ┌──────────────┐
    │  ido.h     │  │ ntp_packet.h│  │ mode_handler.h│
    └─────┬──────┘  └──────┬──────┘  └──────────────┘
          │                │
          └────────┬───────┘
                   ↓
    ┌──────────────┼──────────────┐
    ↓              ↓              ↓
┌────────┐  ┌────────────┐  ┌──────────────┐
│filter.h│  │ntp_algo.h  │  │ time_sync.h  │
└────────┘  └─────┬──────┘  └──────┬───────┘
                  │                │
                  └───────┬────────┘
                          ↓
              ┌───────────┼───────────┐
              ↓           ↓           ↓
         ┌────────┐ ┌────────┐ ┌────────────┐
         │socket.h│ │thread.h│ │leap_sec.h  │
         └───┬────┘ └────────┘ └────────────┘
             ↓
         ┌─────────────┐
         │network4.h   │
         │network6.h   │
         └─────────────┘
```

### Module Responsibilities

| Module | RFC | Responsibility | Dependencies |
|--------|-----|----------------|--------------|
| `ntpd.h/c` | — | Base types, constants, globals, common utilities | None (system headers only) |
| `ido.h/c` | §8.4 | I-DO/Autokey capability negotiation | None |
| `ntp_packet.h/c` | §7.3, §7.5, §8.3 | Packet parsing, extension fields, MAC | `ntpd.h`, `ido.h`, `autokey.h` |
| `ntp_algorithms.h/c` | §11.2.1, §6 | Byzantine fault detection, peer selection | `ntpd.h` |
| `filter.h/c` | §10 | Marx filter, outlier rejection | `ntpd.h` |
| `time_sync.h/c` | §11.3, §11.4 | Clock discipline, leap second, sync | `ntpd.h` |
| `leap_second.h/c` | §11.4 | Leap second file handling | None |
| `threads.h/c` | §5 | Peer & clock threads | None |
| `socket.h/c` | §5 | Socket management, TCP listener | None |
| `network4.h/c` | §5 | IPv4 operations | None |
| `network6.h/c` | §5, §6 | IPv6 operations | None |
| `mode_handler.h/c` | §7.2, §8 | ACL, rate limiting, security | None |
| `autokey.h/c` | §8.4, RFC 5906 | Autokey security protocol, HMAC-SHA1 (parsing only) | `ntpd.h`, `ido.h` |
| `main.c` | — | Entry point, main loop | All modules |
| `config.c` | — | CLI parsing, configuration | `ntpd.h` |

### Design Principles

- **Single Responsibility Principle (SRP):** Each module has one well-defined responsibility
- **Separation of Concerns:** 5-layer architecture with clear boundaries
- **High Cohesion:** Functions within each module are closely related
- **Low Coupling:** Minimal dependencies between modules
- **No Cyclic Dependencies:** Strict hierarchical dependency structure
- **RFC 5905 Compliance:** Module structure mirrors RFC sections

## Building

```bash
# Release build (optimized)
make release

# Debug build (with debug symbols)
make debug

# With sanitizers
make asan    # Address sanitizer
make ubsan   # Undefined behavior sanitizer

# Format code (LLVM style)
make format

# Run static analysis
make lint
```

## Requirements

- GCC 5.0+ or Clang
- Linux kernel 3.0+
- POSIX threads
- systemd (optional)

## Security

- **CERT C** compliant code
- **LLVM Style** formatting
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
- Code formatting check (LLVM style)
- Pre-commit hooks
- Security analysis

## Code Style

We use **LLVM style** for code formatting:

- **clang-format** with LLVM style
- **4-space indentation**
- **160 character line limit**
- **Short functions on single line**

### Format Code

```bash
# Format all files
make format

# Or manually
clang-format -i *.c *.h
```

### Pre-commit Hooks

Install pre-commit hooks:

```bash
pre-commit install
pre-commit run --all-files
```

This will automatically format code before each commit.

## License

BSD-3-Clause - See [LICENSE](LICENSE)

## Contributing

1. Fork repository
2. Create feature branch
3. Make changes (GPG signed)
4. Submit pull request

---

**Related RFCs:** [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905), [RFC 5906](https://www.rfc-editor.org/rfc/rfc5906), [RFC 8915](https://www.rfc-editor.org/rfc/rfc8915)
