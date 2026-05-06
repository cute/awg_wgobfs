# AWG_WGOBFS

AmneziaWG Obfuscation extension for `iptables`.

This project provides a Linux kernel module and a userspace `iptables` library to support the [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go) obfuscation protocol directly in the kernel's netfilter stack.

It allows a standard Linux WireGuard interface to communicate with AmneziaWG clients/servers by stripping/adding obfuscation layers (custom magic headers and random padding) in the `mangle` table.

## Features

- **Custom Magic Headers**: Supports custom values and ranges for `H1`, `H2`, `H3`, and `H4`.
- **Packet Padding**: Supports stripping and adding random padding `S1`, `S2`, `S3`, and `S4` at the beginning of packets.
- **High Performance**: In-place packet modification in kernel space with proper checksum updates.
- **IPv4 & IPv6**: Full support for both address families.

## Build & Installation

### Prerequisites

You need kernel headers and `iptables` development files installed on your system.

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential linux-headers-$(uname -r) iptables-dev pkg-config
```

### Build

```bash
cd awg
make
```

### Install

```bash
sudo make install
```
This will install the kernel module (`awg_wgobfs.ko`) and the iptables library (`libxt_AWG_WGOBFS.so`).

## Usage

The extension must be used in the `mangle` table.

### Server-side (Inbound De-obfuscation)

To accept obfuscated traffic from an AmneziaWG client and turn it into standard WireGuard packets:

```bash
# Example parameters: h1=0x1234, s1=24, h4=0x5678, s4=5
iptables -t mangle -A PREROUTING -p udp --dport 51820 \
    -j AWG_WGOBFS --unobfs --h1 0x1234 --s1 24 --h4 0x5678 --s4 5
```

### Server-side (Outbound Obfuscation)

To obfuscate standard WireGuard responses going back to the client:

```bash
iptables -t mangle -A POSTROUTING -p udp --sport 51820 \
    -j AWG_WGOBFS --obfs --h2 0x2222 --s2 16 --h4 0x5678 --s4 5
```

### Parameters

- `--obfs` / `--unobfs`: Set mode to obfuscate (outbound) or de-obfuscate (inbound).
- `--h1`, `--h2`, `--h3`, `--h4`: Set custom magic headers (supports single values like `123` or ranges like `100-200`).
- `--s1`, `--s2`, `--s3`, `--s4`: Set padding lengths in bytes.

## License

GPL v2

## Author

Li Guangming
