#ifndef _AWG_WG_H
#define _AWG_WG_H

/*
 * Standard WireGuard message types (little-endian uint32 in the first 4 bytes
 * of the UDP payload). The upper 3 bytes are reserved zeros in standard WG,
 * so the on-wire values are 0x01000000 etc. in memory but we compare via
 * le32-to-cpu, yielding 1/2/3/4.
 */
#define WG_HANDSHAKE_INIT       1
#define WG_HANDSHAKE_RESP       2
#define WG_COOKIE_REPLY         3
#define WG_TRANSPORT            4

/*
 * Standard WireGuard message sizes (bytes, excluding any AmneziaWG padding).
 */
#define WG_INIT_SIZE            148
#define WG_RESP_SIZE            92
#define WG_COOKIE_SIZE          64
#define WG_TRANSPORT_HDR_SIZE   16  /* type(4) + receiver(4) + counter(8) */

#endif /* _AWG_WG_H */
