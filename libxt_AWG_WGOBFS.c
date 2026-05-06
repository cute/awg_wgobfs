/*
 * libxt_AWG_WGOBFS.c - Userspace iptables extension for AmneziaWG obfuscation
 *
 * Usage:
 *   iptables -t mangle -A PREROUTING -p udp --dport 51820 \
 *     -j AWG_WGOBFS --unobfs --h1 12345678 --h2 87654321 \
 *     --h3 11111111 --h4 22222222 --s1 24 --s2 16 --s3 0 --s4 8
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <xtables.h>
#include <stdint.h>
#include "awg_wgobfs.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum {
	FLAGS_MODE = 1 << 0,
	FLAGS_H1   = 1 << 1,
	FLAGS_H2   = 1 << 2,
	FLAGS_H3   = 1 << 3,
	FLAGS_H4   = 1 << 4,
};

enum {
	OPT_H1 = 0,
	OPT_H2,
	OPT_H3,
	OPT_H4,
	OPT_S1,
	OPT_S2,
	OPT_S3,
	OPT_S4,
	OPT_OBFS,
	OPT_UNOBFS,
};

static const struct option awg_wgobfs_opts[] = {
	{.name = "h1",     .has_arg = true,  .val = OPT_H1},
	{.name = "h2",     .has_arg = true,  .val = OPT_H2},
	{.name = "h3",     .has_arg = true,  .val = OPT_H3},
	{.name = "h4",     .has_arg = true,  .val = OPT_H4},
	{.name = "s1",     .has_arg = true,  .val = OPT_S1},
	{.name = "s2",     .has_arg = true,  .val = OPT_S2},
	{.name = "s3",     .has_arg = true,  .val = OPT_S3},
	{.name = "s4",     .has_arg = true,  .val = OPT_S4},
	{.name = "obfs",   .has_arg = false, .val = OPT_OBFS},
	{.name = "unobfs", .has_arg = false, .val = OPT_UNOBFS},
	{NULL},
};

static void awg_wgobfs_help(void)
{
	printf(
	"AWG_WGOBFS target options:\n"
	"  --obfs / --unobfs                        obfuscation direction\n"
	"  --h1 <uint32>[-<uint32>]                 magic header for Initiation\n"
	"  --h2 <uint32>[-<uint32>]                 magic header for Response\n"
	"  --h3 <uint32>[-<uint32>]                 magic header for Cookie Reply\n"
	"  --h4 <uint32>[-<uint32>]                 magic header for Transport\n"
	"  --s1 <uint16>                            padding length for Initiation\n"
	"  --s2 <uint16>                            padding length for Response\n"
	"  --s3 <uint16>                            padding length for Cookie Reply\n"
	"  --s4 <uint16>                            padding length for Transport\n"
	);
}

static void parse_header(const char *s, struct awg_header *h)
{
	char *end;

	h->start = strtoul(s, &end, 0);
	if (*end == '-')
		h->end = strtoul(end + 1, NULL, 0);
	else
		h->end = h->start;

	if (h->end < h->start)
		xtables_error(PARAMETER_PROBLEM,
			      "AWG_WGOBFS: header range end < start");
}

static void print_header(const char *name, const struct awg_header *h)
{
	if (h->start == h->end)
		printf(" --%s %u", name, h->start);
	else
		printf(" --%s %u-%u", name, h->start, h->end);
}

static int awg_wgobfs_parse(int c, char **argv, int invert,
			     unsigned int *flags, const void *entry,
			     struct xt_entry_target **target)
{
	struct xt_awg_wgobfs_info *info = (void *)(*target)->data;

	switch (c) {
	case OPT_H1:
		parse_header(optarg, &info->h1);
		*flags |= FLAGS_H1;
		break;
	case OPT_H2:
		parse_header(optarg, &info->h2);
		*flags |= FLAGS_H2;
		break;
	case OPT_H3:
		parse_header(optarg, &info->h3);
		*flags |= FLAGS_H3;
		break;
	case OPT_H4:
		parse_header(optarg, &info->h4);
		*flags |= FLAGS_H4;
		break;
	case OPT_S1:
		info->s1 = atoi(optarg);
		break;
	case OPT_S2:
		info->s2 = atoi(optarg);
		break;
	case OPT_S3:
		info->s3 = atoi(optarg);
		break;
	case OPT_S4:
		info->s4 = atoi(optarg);
		break;
	case OPT_OBFS:
		info->mode = XT_MODE_OBFS;
		*flags |= FLAGS_MODE;
		break;
	case OPT_UNOBFS:
		info->mode = XT_MODE_UNOBFS;
		*flags |= FLAGS_MODE;
		break;
	default:
		return 0;
	}
	return 1;
}

static void awg_wgobfs_check(unsigned int flags)
{
	if (!(flags & FLAGS_MODE))
		xtables_error(PARAMETER_PROBLEM,
			      "AWG_WGOBFS: --obfs or --unobfs is required.");
}

static void awg_wgobfs_print(const void *entry,
			      const struct xt_entry_target *target,
			      int numeric)
{
	const struct xt_awg_wgobfs_info *info = (const void *)target->data;

	printf(" AWG_WGOBFS %s",
	       info->mode == XT_MODE_OBFS ? "obfs" : "unobfs");
	print_header("h1", &info->h1);
	print_header("h2", &info->h2);
	print_header("h3", &info->h3);
	print_header("h4", &info->h4);
	printf(" s1 %u s2 %u s3 %u s4 %u",
	       info->s1, info->s2, info->s3, info->s4);
}

static void awg_wgobfs_save(const void *entry,
			     const struct xt_entry_target *target)
{
	const struct xt_awg_wgobfs_info *info = (const void *)target->data;

	printf(" --%s", info->mode == XT_MODE_OBFS ? "obfs" : "unobfs");
	print_header("h1", &info->h1);
	print_header("h2", &info->h2);
	print_header("h3", &info->h3);
	print_header("h4", &info->h4);
	printf(" --s1 %u --s2 %u --s3 %u --s4 %u",
	       info->s1, info->s2, info->s3, info->s4);
}

static struct xtables_target awg_wgobfs_reg[] = {
	{
		.version       = XTABLES_VERSION,
		.name          = "AWG_WGOBFS",
		.revision      = 0,
		.family        = NFPROTO_IPV4,
		.size          = XT_ALIGN(sizeof(struct xt_awg_wgobfs_info)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_awg_wgobfs_info)),
		.help          = awg_wgobfs_help,
		.parse         = awg_wgobfs_parse,
		.final_check   = awg_wgobfs_check,
		.print         = awg_wgobfs_print,
		.save          = awg_wgobfs_save,
		.extra_opts    = awg_wgobfs_opts,
	},
	{
		.version       = XTABLES_VERSION,
		.name          = "AWG_WGOBFS",
		.revision      = 0,
		.family        = NFPROTO_IPV6,
		.size          = XT_ALIGN(sizeof(struct xt_awg_wgobfs_info)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_awg_wgobfs_info)),
		.help          = awg_wgobfs_help,
		.parse         = awg_wgobfs_parse,
		.final_check   = awg_wgobfs_check,
		.print         = awg_wgobfs_print,
		.save          = awg_wgobfs_save,
		.extra_opts    = awg_wgobfs_opts,
	},
};

static __attribute__((constructor)) void awg_wgobfs_ldr(void)
{
	xtables_register_targets(awg_wgobfs_reg, ARRAY_SIZE(awg_wgobfs_reg));
}
