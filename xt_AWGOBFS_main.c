/*
 * xt_AWGOBFS_main.c - AmneziaWG obfuscation/de-obfuscation iptables target
 *
 * This kernel module implements an iptables target that transforms standard
 * WireGuard UDP packets into AmneziaWG-obfuscated form (and vice versa).
 *
 * Obfuscation (outbound, --obfs):
 *   1. Read the standard WG type field (LE uint32 at offset 0).
 *   2. Prepend S_n bytes of random padding before the WG payload.
 *   3. Replace the type field with a custom magic header H_n.
 *   4. Update IP total length / IPv6 payload length and UDP length + checksum.
 *
 * De-obfuscation (inbound, --unobfs):
 *   1. Determine which message type this is by checking total size and
 *      validating the magic header H_n at offset S_n.
 *   2. Overwrite the custom type with the standard WG type (1/2/3/4).
 *   3. Strip the S_n padding bytes from the front.
 *   4. Update IP/UDP headers and checksums.
 *
 * After de-obfuscation the packet looks like a standard WireGuard packet and
 * can be consumed by the kernel wireguard module or forwarded elsewhere.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/ip.h>
#include <net/udp.h>
#include <linux/random.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
#include <linux/ipv6.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/ipv6.h>
#endif

#include "xt_AWGOBFS.h"
#include "wg.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Li Guangming");
MODULE_DESCRIPTION("AmneziaWG Obfuscation Target for iptables");
MODULE_VERSION("0.1");
MODULE_ALIAS("xt_AWGOBFS");

/* -------------------------------------------------------------------------- */
/* Helper: header range matching                                              */
/* -------------------------------------------------------------------------- */

static inline bool header_match(u32 val, const struct awg_header *h)
{
	return val >= h->start && val <= h->end;
}

static inline u32 generate_header(const struct awg_header *h)
{
	u32 r;

	if (h->start == h->end)
		return h->start;
	get_random_bytes(&r, sizeof(r));
	return h->start + (r % (h->end - h->start + 1));
}

/* -------------------------------------------------------------------------- */
/* Helper: make skb writable                                                  */
/* -------------------------------------------------------------------------- */

static int ensure_writable(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
	return skb_ensure_writable(skb, skb->len);
#else
	return !skb_make_writable(skb, skb->len) ? -1 : 0;
#endif
}

/* -------------------------------------------------------------------------- */
/* Checksum recalculation                                                     */
/* -------------------------------------------------------------------------- */

static void recalc_checksums_v4(struct sk_buff *skb, int delta)
{
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *uh = udp_hdr(skb);

	iph->tot_len = htons(ntohs(iph->tot_len) + delta);
	iph->tos = 0; /* DiffServ 0x88 looks distinct, reset */
	iph->check = 0;
	ip_send_check(iph);

	uh->len = htons(ntohs(uh->len) + delta);
	skb->ip_summed = CHECKSUM_NONE;
	uh->check = 0;
	uh->check = csum_tcpudp_magic(
		iph->saddr, iph->daddr, ntohs(uh->len), IPPROTO_UDP,
		csum_partial((char *)uh, ntohs(uh->len), 0));
}

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
static void recalc_checksums_v6(struct sk_buff *skb, int delta)
{
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct udphdr *uh = udp_hdr(skb);

	ip6h->payload_len = htons(ntohs(ip6h->payload_len) + delta);
	ip6_flow_hdr(ip6h, 0, htonl(0)); /* reset DiffServ */

	uh->len = htons(ntohs(uh->len) + delta);
	skb->ip_summed = CHECKSUM_NONE;
	uh->check = 0;
	uh->check = csum_ipv6_magic(
		&ip6h->saddr, &ip6h->daddr, ntohs(uh->len), IPPROTO_UDP,
		csum_partial((char *)uh, ntohs(uh->len), 0));
}
#endif

/* -------------------------------------------------------------------------- */
/* Core: de-obfuscation (inbound)                                             */
/* -------------------------------------------------------------------------- */

/*
 * Determine the message type from an obfuscated packet.
 *
 * Returns: standard WG type (1-4) on success, 0 if no match.
 * *out_padding is set to the number of padding bytes to strip.
 *
 * The logic mirrors amneziawg-go DeterminePacketTypeAndPadding():
 *  - For fixed-size messages (Init/Resp/Cookie): size must exactly equal
 *    S_n + standard_size.
 *  - For variable-size Transport: size must be >= S_n + WG_TRANSPORT_HDR_SIZE.
 *  - The magic header at offset S_n must fall within the H_n range.
 */
static u32 determine_type(const u8 *payload, unsigned int payload_len,
			   const struct xt_awgobfs_info *info,
			   int *out_padding)
{
	u32 type;

	/* Initiation: fixed 148 bytes */
	if (payload_len == (unsigned int)info->s1 + WG_INIT_SIZE &&
	    payload_len >= (unsigned int)info->s1 + 4) {
		type = get_unaligned_le32(payload + info->s1);
		if (header_match(type, &info->h1)) {
			*out_padding = info->s1;
			return WG_HANDSHAKE_INIT;
		}
	}

	/* Response: fixed 92 bytes */
	if (payload_len == (unsigned int)info->s2 + WG_RESP_SIZE &&
	    payload_len >= (unsigned int)info->s2 + 4) {
		type = get_unaligned_le32(payload + info->s2);
		if (header_match(type, &info->h2)) {
			*out_padding = info->s2;
			return WG_HANDSHAKE_RESP;
		}
	}

	/* Cookie Reply: fixed 64 bytes */
	if (payload_len == (unsigned int)info->s3 + WG_COOKIE_SIZE &&
	    payload_len >= (unsigned int)info->s3 + 4) {
		type = get_unaligned_le32(payload + info->s3);
		if (header_match(type, &info->h3)) {
			*out_padding = info->s3;
			return WG_COOKIE_REPLY;
		}
	}

	/* Transport: variable size, at least header */
	if (payload_len >= (unsigned int)info->s4 + WG_TRANSPORT_HDR_SIZE) {
		type = get_unaligned_le32(payload + info->s4);
		if (header_match(type, &info->h4)) {
			*out_padding = info->s4;
			return WG_TRANSPORT;
		}
	}

	*out_padding = 0;
	return 0;
}

static unsigned int do_unobfs(struct sk_buff *skb,
			      const struct xt_awgobfs_info *info,
			      unsigned short family)
{
	struct udphdr *uh;
	u8 *payload;
	unsigned int payload_len;
	u32 standard_type;
	int padding;

	if (ensure_writable(skb))
		return NF_DROP;

	uh = udp_hdr(skb);
	payload = (u8 *)uh + sizeof(struct udphdr);
	payload_len = ntohs(uh->len) - sizeof(struct udphdr);

	if (payload_len < 4)
		return XT_CONTINUE; /* too short, pass through */

	standard_type = determine_type(payload, payload_len, info, &padding);
	if (standard_type == 0)
		return XT_CONTINUE; /* not an AWG packet, pass through */

	/*
	 * Overwrite the custom magic header with the standard WG type.
	 * The WG type field is a LE uint32 at offset S_n in the payload.
	 */
	put_unaligned_le32(standard_type, payload + padding);

	if (padding > 0) {
		/* Strip the padding: shift payload left */
		memmove(payload, payload + padding, payload_len - padding);
		skb_trim(skb, skb->len - padding);

		/* Recalculate checksums */
		if (family == NFPROTO_IPV4) {
			recalc_checksums_v4(skb, -padding);
		}
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
		else {
			recalc_checksums_v6(skb, -padding);
		}
#endif
	}

	return XT_CONTINUE;
}

/* -------------------------------------------------------------------------- */
/* Core: obfuscation (outbound)                                               */
/* -------------------------------------------------------------------------- */

static unsigned int do_obfs(struct sk_buff *skb,
			    const struct xt_awgobfs_info *info,
			    unsigned short family)
{
	struct udphdr *uh;
	u8 *payload;
	unsigned int payload_len;
	u32 type, custom_type;
	int padding;
	int extra;

	if (ensure_writable(skb))
		return NF_DROP;

	uh = udp_hdr(skb);
	payload = (u8 *)uh + sizeof(struct udphdr);
	payload_len = ntohs(uh->len) - sizeof(struct udphdr);

	if (payload_len < 4)
		return XT_CONTINUE;

	type = get_unaligned_le32(payload);
	switch (type) {
	case WG_HANDSHAKE_INIT:
		custom_type = generate_header(&info->h1);
		padding = info->s1;
		break;
	case WG_HANDSHAKE_RESP:
		custom_type = generate_header(&info->h2);
		padding = info->s2;
		break;
	case WG_COOKIE_REPLY:
		custom_type = generate_header(&info->h3);
		padding = info->s3;
		break;
	case WG_TRANSPORT:
		custom_type = generate_header(&info->h4);
		padding = info->s4;
		break;
	default:
		return XT_CONTINUE; /* not a WG packet, pass through */
	}

	if (padding > 0) {
		/* Expand the skb to hold the padding */
		extra = padding - skb_tailroom(skb);
		if (extra > 0) {
			if (pskb_expand_head(skb, 0, extra, GFP_ATOMIC))
				return NF_DROP;
		}
		/*
		 * After pskb_expand_head the header pointers may be invalid.
		 * Re-fetch them unconditionally to be safe.
		 */
		uh = udp_hdr(skb);
		payload = (u8 *)uh + sizeof(struct udphdr);

		skb_put(skb, padding);

		/* Shift the original payload right to make room for padding */
		memmove(payload + padding, payload, payload_len);

		/* Fill the padding with random bytes */
		get_random_bytes(payload, padding);

		/* Recalculate checksums */
		if (family == NFPROTO_IPV4) {
			recalc_checksums_v4(skb, padding);
		}
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
		else {
			recalc_checksums_v6(skb, padding);
		}
#endif
	}

	/* Overwrite the type field (now at offset `padding`) */
	uh = udp_hdr(skb);
	payload = (u8 *)uh + sizeof(struct udphdr);
	put_unaligned_le32(custom_type, payload + padding);

	return XT_CONTINUE;
}

/* -------------------------------------------------------------------------- */
/* xtables target callbacks                                                   */
/* -------------------------------------------------------------------------- */

static unsigned int
xt_awgobfs_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_awgobfs_info *info = par->targinfo;
	struct iphdr *iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_UDP)
		return XT_CONTINUE;

	if (info->mode == XT_MODE_OBFS)
		return do_obfs(skb, info, NFPROTO_IPV4);
	else
		return do_unobfs(skb, info, NFPROTO_IPV4);
}

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
static unsigned int
xt_awgobfs_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_awgobfs_info *info = par->targinfo;
	struct ipv6hdr *ip6h = ipv6_hdr(skb);

	if (ip6h->nexthdr != IPPROTO_UDP)
		return XT_CONTINUE;

	if (info->mode == XT_MODE_OBFS)
		return do_obfs(skb, info, NFPROTO_IPV6);
	else
		return do_unobfs(skb, info, NFPROTO_IPV6);
}
#endif

/* -------------------------------------------------------------------------- */
/* checkentry: restrict to mangle table                                       */
/* -------------------------------------------------------------------------- */

static int xt_awgobfs_checkentry(const struct xt_tgchk_param *par)
{
	if (strcmp(par->table, "mangle")) {
		pr_warn("AWGOBFS: can only be called from mangle table\n");
		return -EINVAL;
	}
	return 0;
}

/* -------------------------------------------------------------------------- */
/* Module registration                                                        */
/* -------------------------------------------------------------------------- */

static struct xt_target xt_awgobfs_reg[] __read_mostly = {
	{
		.name		= "AWGOBFS",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.table		= "mangle",
		.target		= xt_awgobfs_tg4,
		.targetsize	= sizeof(struct xt_awgobfs_info),
		.checkentry	= xt_awgobfs_checkentry,
		.me		= THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name		= "AWGOBFS",
		.revision	= 0,
		.family		= NFPROTO_IPV6,
		.table		= "mangle",
		.target		= xt_awgobfs_tg6,
		.targetsize	= sizeof(struct xt_awgobfs_info),
		.checkentry	= xt_awgobfs_checkentry,
		.me		= THIS_MODULE,
	},
#endif
};

static int __init xt_awgobfs_init(void)
{
	return xt_register_targets(xt_awgobfs_reg, ARRAY_SIZE(xt_awgobfs_reg));
}

static void __exit xt_awgobfs_exit(void)
{
	xt_unregister_targets(xt_awgobfs_reg, ARRAY_SIZE(xt_awgobfs_reg));
}

module_init(xt_awgobfs_init);
module_exit(xt_awgobfs_exit);
