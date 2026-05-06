# xt_awgobfs

AmneziaWG obfuscation extension for `iptables`.

This project provides a Linux kernel module and a userspace `iptables` library
to support the [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go)
obfuscation protocol directly in the kernel's netfilter stack.

It allows a standard Linux WireGuard interface to communicate with AmneziaWG
clients/servers by stripping/adding obfuscation layers (custom magic headers
and random padding) in the `mangle` table.

## Features

- **Custom Magic Headers**: Supports custom values and ranges for `H1`–`H4`.
- **Packet Padding**: Supports stripping and adding random padding `S1`–`S4`
  at the beginning of packets.
- **High Performance**: In-place packet modification in kernel space with
  proper checksum updates.
- **IPv4 & IPv6**: Full support for both address families.

## Build & Installation

### Prerequisites

You need kernel headers and `iptables` development files installed.

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential linux-headers-$(uname -r) \
    iptables-dev pkg-config autoconf automake libtool
```

### Build (autotools)

```bash
./autogen.sh
./configure
make
sudo make install
```

### Build (manual)

```bash
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
gcc -fPIC -shared -o libxt_AWGOBFS.so libxt_AWGOBFS.c $(pkg-config --cflags xtables)
```

## Usage

The extension must be used in the `mangle` table. The target name is
**`AWGOBFS`**.

### Server-side (Inbound De-obfuscation)

To accept obfuscated traffic from an AmneziaWG client and turn it into
standard WireGuard packets:

```bash
iptables -t mangle -A PREROUTING -p udp --dport 51820 \
    -j AWGOBFS --unobfs \
    --h1 0x1234 --h2 0x5678 --h3 0x9abc --h4 0xdef0 \
    --s1 24 --s2 16 --s3 0 --s4 8
```

### Server-side (Outbound Obfuscation)

To obfuscate standard WireGuard responses going back to the client:

```bash
iptables -t mangle -A POSTROUTING -p udp --sport 51820 \
    -j AWGOBFS --obfs \
    --h1 0x1234 --h2 0x5678 --h3 0x9abc --h4 0xdef0 \
    --s1 24 --s2 16 --s3 0 --s4 8
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `--obfs` / `--unobfs` | Set mode to obfuscate (outbound) or de-obfuscate (inbound) |
| `--h1` .. `--h4` | Custom magic headers (single value `123` or range `100-200`) |
| `--s1` .. `--s4` | Padding lengths in bytes |

## License

GPL v2

## Author

Li Guangming
