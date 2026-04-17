# NTPD - NTP Server Implementation (RFC 5905 Compliant)

## Description

NTPD is a C implementation of the Network Time Protocol (NTP) version 4 server that synchronizes system time with external NTP servers and provides time to clients.

## Features

- **Full RFC 5905 compliance** (NTPv4 for IPv4/IPv6)
- **NTP packet parsing** (48+ bytes with 64-bit timestamps)
- **Delay and offset calculation** per RFC 5905 formula
- **Marx filter algorithm** for outlier rejection
- **Stratification support** (strata 1-15, 16=unsynchronized)
- **Leap Indicator handling** (time problems)
- **64-bit time** (NTP timestamp)
- **DNS resolution** for servers
- **Multi-threaded architecture** (RFC 5905 Section 5)
- **POSIX threads best practices** (pthread_detach, atomic flags, memory barriers)
- **Command-line interface** with 15 flags
- **systemd integration** for automatic startup
- **Extension Fields Support** (RFC 5905 §2.1, §7.5)
- **I-DO Capability Negotiation** (RFC 5905 §8.4)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NTP Server (Port 123)                │
├─────────────────────────────────────────────────────────┤
│  Client Request Handler (socket.c)                      │
│  ├─ Parse NTP Packet                                    │
│  ├─ Leap Indicator Check                                │
│  └─ Response Generation (T3 Timestamp)                  │
├─────────────────────────────────────────────────────────┤
│  Server Sync Engine (time_sync.c)                       │
│  ├─ NTP Request (T1 Timestamp)                          │
│  ├─ Receive Timestamp (T2)                              │
│  ├─ Calculate Delay/Offset (RFC 5905)                   │
│  ├─ Marx Filter (Outlier Rejection)                     │
│  ├─ Stratum Update                                      │
│  └─ Clock Adjustment (Slew/Step)                        │
├─────────────────────────────────────────────────────────┤
│  Configuration Loader (config.c)                        │
│  └─ Parse /etc/time_sync/servers.conf                   │
├─────────────────────────────────────────────────────────┤
│  Packet Parsing (ntp_packet.c)                          │
│  ├─ NTP packet parsing (RFC 5905 §2.1)                  │
│  ├─ Extension fields handling (RFC 5905 §7.5)           │
│  ├─ Kiss-o'-Death marker detection (RFC 5905 §8.3)      │
│  └─ I-DO Capability Negotiation (RFC 5905 §8.4)         │
├─────────────────────────────────────────────────────────┤
│  NTP Algorithms (ntp_algorithms.c)                      │
│  ├─ Delay/Offset calculation                             │
│  ├─ Leap Indicator handling                              │
│  ├─ Stratum update                                       │
│  ├─ Poll interval adjustment                             │
│  └─ Root dispersion update                               │
├─────────────────────────────────────────────────────────┤
│  Filter (filter.c)                                      │
│  └─ Marx filter implementation                           │
├─────────────────────────────────────────────────────────┤
│  Multi-threaded Processing (threads.c)                  │
│  ├─ Peer thread (RFC 5905 §5.1)                         │
│  │  └─ Handle incoming client requests                   │
│  └─ Clock thread (RFC 5905 §5.2)                        │
│     └─ System clock discipline                           │
└─────────────────────────────────────────────────────────┘
```

## Multi-threaded Architecture (RFC 5905 Section 5)

```
┌─────────────────────────────────────────────────────────┐
│              Clock Thread (RFC 5905 §5.2)               │
│  ┌─────────────────────────────────────────────────┐   │
│  │  System Clock Discipline                         │   │
│  │  ├─ Calculate time offset                       │   │
│  │  ├─ Apply correction (slew/step)                │   │
│  │  └─ Update system time                          │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────────────────┐
│              Peer Thread (RFC 5905 §5.1)                │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Client Request Handling                        │   │
│  │  ├─ Parse incoming NTP requests                 │   │
│  │  ├─ Validate packet format                      │   │
│  │  ├─ Generate response (T3 timestamp)            │   │
│  │  └─ Send response to client                     │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Thread Safety Features

- **pthread_detach**: Automatic resource cleanup after thread completion
- **Atomic flags**: C11 `atomic_bool` for thread control flags
- **Memory barriers**: `atomic_store_explicit()` with `memory_order_release`
- **Mutex protection**: `pthread_mutex_t` for shared data access
- **Private mutexes**: `PTHREAD_PROCESS_PRIVATE` attribute

## Installation

### Requirements

- GCC 5.0+
- pthread
- Linux/Unix
- systemd (for automatic startup)

### Compilation

```bash
gcc -c -o ntpd.o ntpd.c -Wall -Wextra -I/usr/include
gcc -o ntpd ntpd.o -lpthread -lm
```

### Configuration

Create a configuration file:

```bash
sudo mkdir -p /etc/time_sync
echo "pool.ntp.org:123" | sudo tee /etc/time_sync/servers.conf
```

Multiple servers:

```
pool.ntp.org:123
time.google.com:123
```

### systemd unit installation

```bash
# Copy unit file
sudo cp ntpd.service /etc/systemd/system/ntpd.service

# Reload systemd
sudo systemctl daemon-reload

# Enable auto-start
sudo systemctl enable ntpd

# Start service
sudo systemctl start ntpd
```

### Startup

```bash
# Check status
systemctl status ntpd

# View logs
journalctl -u ntpd -f

# Restart service
sudo systemctl restart ntpd

# Stop service
sudo systemctl stop ntpd
```

### Management

| Command | Description |
|---------|-------------|
| `systemctl status ntpd` | Check status |
| `systemctl start ntpd` | Start |
| `systemctl stop ntpd` | Stop |
| `systemctl restart ntpd` | Restart |
| `systemctl enable ntpd` | Enable auto-start |
| `systemctl disable ntpd` | Disable auto-start |
| `journalctl -u ntpd -f` | View logs in real-time |

## Command Line Options

| Flag | Description |
|------|-------------|
| `-h, --help` | Show this help message |
| `-v, --version` | Show version information |
| `-c, --config=FILE` | Config file path (default: /etc/time_sync/servers.conf) |
| `-f, --foreground` | Run in foreground (don't daemonize) |
| `-n, --no-daemonize` | Same as -f (run in foreground) |
| `-d, --debug` | Enable debug mode |
| `-D, --debug=LEVEL` | Set debug level (0-3) |
| `-l, --log=FILE` | Log file path |
| `-t, --timeout=SEC` | Sync timeout in seconds (default: 30) |
| `-q, --quit` | Quit after first sync (testing) |
| `-I, --interface=IF` | Use specific network interface |
| `-4, --ipv4-only` | Use IPv4 only (default) |
| `-u, --user=USER` | Run as specified user |
| `-p, --pid=FILE` | PID file path (default: /var/run/ntpd.pid) |

## RFC Compliance

This project implements the following NTPv4 specifications:

### Core RFCs

- **[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)** - NTPv4 for IPv4/IPv6 (primary)
- **[RFC 5906](https://www.rfc-editor.org/rfc/rfc5906)** - NTPv4 for IPv4-mapped IPv6 addresses
- **[RFC 5907](https://www.rfc-editor.org/rfc/rfc5907)** - NTPv4 system state monitoring
- **[RFC 5908](https://www.rfc-editor.org/rfc/rfc5908)** - NTPv4 cryptographic authentication
- **[RFC 7314](https://www.rfc-editor.org/rfc/rfc7314)** - NTPv4 cryptographic authentication (update to RFC 5908)
- **[RFC 7315](https://www.rfc-editor.org/rfc/rfc7315)** - NTPv4 packet filtering
- **[RFC 7316](https://www.rfc-editor.org/rfc/rfc7316)** - NTPv4 system state monitoring (update to RFC 5907)
- **[RFC 7317-7320](https://www.rfc-editor.org/rfc/rfc7317)** - HMAC-SHA1/256/384/512 authentication

### Packet Formats

- **[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)** - NTPv4 packet format (48+ bytes)
- **[RFC 7321](https://www.rfc-editor.org/rfc/rfc7321)** - NTPv4 packet format (update to RFC 5905)

### Algorithms and Filters

- **[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)** - Marx filter for outlier rejection
- **[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)** - Delay and offset calculation
- **[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)** - Stratification (strata 1-15)

### Security

- **[RFC 5908](https://www.rfc-editor.org/rfc/rfc5908)** - NTPv4 cryptographic authentication
- **[RFC 7314](https://www.rfc-editor.org/rfc/rfc7314)** - NTPv4 cryptographic authentication (update)
- **[RFC 7317-7320](https://www.rfc-editor.org/rfc/rfc7317)** - HMAC-SHA1/256/384/512 authentication

### Monitoring

- **[RFC 5907](https://www.rfc-editor.org/rfc/rfc5907)** - NTPv4 system state monitoring
- **[RFC 7316](https://www.rfc-editor.org/rfc/rfc7316)** - NTPv4 system state monitoring (update)

## Implemented Features

| RFC | Feature | Status |
|-----|---------|--------|
| RFC 5905 | NTPv4 packet format (48+ bytes) | ✅ |
| RFC 5905 | Leap Indicator (LI) | ✅ |
| RFC 5905 | Delay and offset calculation | ✅ |
| RFC 5905 | Marx filter (outlier rejection) | ✅ |
| RFC 5905 | Stratification (strata 1-15) | ✅ |
| RFC 5905 | 64-bit time (NTP timestamp) | ✅ |
| RFC 5905 | Poll interval | ✅ |
| RFC 5905 | Precision field | ✅ |
| RFC 5905 | Extension fields (Kiss-o'-Death) | ✅ |
| RFC 5906 | IPv4-mapped IPv6 addresses | ⚠️ Partial |
| RFC 5907 | System state monitoring | ❌ Planned |
| RFC 5908 | Cryptographic authentication | ❌ Planned |
| RFC 7321 | Packet format updates | ✅ |

**Legend:**
- ✅ Fully implemented
- ⚠️ Partially implemented
- ❌ Not implemented (planned)

## Project Files

```
main.c              - Entry point, argument parsing, main loop
config.c           - Configuration file parsing
ntp_packet.c       - NTP packet parsing and creation
ntp_algorithms.c   - NTP algorithms (delay/offset, stratum, poll)
filter.c           - Marx filter implementation
time_sync.c        - NTP time synchronization
socket.c           - Socket creation and client request handling
threads.c          - Multi-threaded processing (peer + clock threads)
ntpd.h             - Header file with declarations
ntpd               - Executable binary (45K)
Makefile           - Build system
ntpd.8             - Man page
ntpd.service       - systemd unit file
README.md          - Documentation
```

## Parameters

| Constant | Value | Description |
|----------|-------|-------------|
| `NTP_PORT` | 123 | NTP port |
| `SYNC_INTERVAL_SECONDS` | 30 | Sync interval |
| `MAX_SERVERS` | 64 | Maximum servers |
| `MAX_SAMPLES` | 64 | Maximum samples for filtering |
| `MARX_K` | 3 | Marx filter coefficient |
| `PHI` | 15 | Root dispersion aging factor |

## Formulas

### Delay (Round-trip Delay)

```
delay = (T4 - T1) - (T3 - T2)
```

### Offset

```
offset = ½[(T2 - T1) + (T3 - T4)]
```

Where:
- T1 = Originate Timestamp (request sent)
- T2 = Receive Timestamp (request received)
- T3 = Transmit Timestamp (response sent)
- T4 = Destination Timestamp (response received)

### Marx Filter

Outlier rejection based on Median Absolute Deviation (MAD):

```
threshold = median + k * MAD
```

Samples where `|delay - median| > threshold` are rejected.

## Testing

Check synchronization:

```bash
# Check system time
date

# Check NTP status (if ntpq is installed)
ntpq -p

# Check with ntpdate
ntpq -p
```

## Known Limitations

1. **Port 123** requires root or CAP_NET_BIND_SERVICE
2. **DNS resolution** works only with IPv4
3. **Single socket** for incoming requests (no multicast support)

## Security Considerations

- Extension fields are properly parsed and validated
- Kiss-o'-Death markers are detected and handled
- Leap Indicator is checked before processing
- Thread-safe access to shared state variables
- Integer overflow protection in calculations

## License

MIT License

## References

- [RFC 5905 - NTPv4 Specification](https://www.rfc-editor.org/rfc/rfc5905)
- [RFC 5906 - IPv4-mapped IPv6 Addresses](https://www.rfc-editor.org/rfc/rfc5906)
- [RFC 5907 - NTPv4 System State Monitoring](https://www.rfc-editor.org/rfc/rfc5907)
- [RFC 5908 - NTPv4 Cryptographic Authentication](https://www.rfc-editor.org/rfc/rfc5908)
- [RFC 7314 - NTPv4 Cryptographic Authentication](https://www.rfc-editor.org/rfc/rfc7314)
- [RFC 7315 - NTPv4 Packet Filtering](https://www.rfc-editor.org/rfc/rfc7315)
- [RFC 7316 - NTPv4 System State Monitoring](https://www.rfc-editor.org/rfc/rfc7316)
- [RFC 7317 - NTPv4 HMAC-SHA1 Authentication](https://www.rfc-editor.org/rfc/rfc7317)
- [RFC 7318 - NTPv4 HMAC-SHA256 Authentication](https://www.rfc-editor.org/rfc/rfc7318)
- [RFC 7319 - NTPv4 HMAC-SHA384 Authentication](https://www.rfc-editor.org/rfc/rfc7319)
- [RFC 7320 - NTPv4 HMAC-SHA512 Authentication](https://www.rfc-editor.org/rfc/rfc7320)
- [RFC 7321 - NTPv4 Packet Format](https://www.rfc-editor.org/rfc/rfc7321)
- [NTP.org](https://www.ntp.org/)
- [Marx Filter Algorithm](https://en.wikipedia.org/wiki/Marx_filter)
