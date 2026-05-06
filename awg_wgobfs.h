/*
 * awg_wgobfs.h - Shared header for AmneziaWG iptables obfuscation extension
 *
 * This header is shared between the kernel module and the userspace iptables
 * library. It must be kept in sync on both sides.
 */
#ifndef _AWG_WGOBFS_H
#define _AWG_WGOBFS_H

/*
 * Use <stdint.h> in userspace, <linux/types.h> in kernel. The header is
 * included by both, so we guard the include.
 */
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define XT_MODE_OBFS   0
#define XT_MODE_UNOBFS 1

/*
 * awg_header represents a magic header value or range.
 * AmneziaWG stores the type field as a little-endian uint32 in the first 4
 * bytes of the WG message. Standard WG uses 1/2/3/4 (with the upper 3 bytes
 * being reserved zeros). AmneziaWG replaces these with arbitrary uint32 values.
 */
struct awg_header {
    uint32_t start;
    uint32_t end;
};

/*
 * xt_awg_wgobfs_info is the configuration blob passed from userspace to the
 * kernel module via setsockopt.
 *
 * Padding must be explicit to avoid ABI mismatches between userspace and
 * kernel (different compilers / alignment).
 */
struct xt_awg_wgobfs_info {
    uint8_t mode;           /* XT_MODE_OBFS or XT_MODE_UNOBFS */
    uint8_t _pad[3];        /* explicit padding for alignment */
    struct awg_header h1;   /* Handshake Initiation header */
    struct awg_header h2;   /* Handshake Response header */
    struct awg_header h3;   /* Cookie Reply header */
    struct awg_header h4;   /* Transport Data header */
    uint16_t s1;            /* Initiation padding length */
    uint16_t s2;            /* Response padding length */
    uint16_t s3;            /* Cookie Reply padding length */
    uint16_t s4;            /* Transport Data padding length */
};

#endif /* _AWG_WGOBFS_H */
