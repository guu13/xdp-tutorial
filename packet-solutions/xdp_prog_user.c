/* SPDX-License-Identifier: GPL-2.0 */

static const char *__doc__ = "XDP redirect helper\n"
	" - Allows to populate/query tx_port and redirect_params maps\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#include "../common/xdp_stats_kern_user.h"

#include <linux/in6.h>

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"redirect-dev",         required_argument,	NULL, 'r' },
	 "Redirect to device <ifname>", "<ifname>", true},

	{{"src-mac", required_argument, NULL, 'L' },
	 "Source MAC address of <dev>", "<mac>", true },

	{{"dest-mac", required_argument, NULL, 'R' },
	 "Destination MAC address of <redirect-dev>", "<mac>", true },

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static int parse_u8(char *str, unsigned char *x)
{
	unsigned long z;

	z = strtoul(str, 0, 16);
	if (z > 0xff)
		return -1;

	if (x)
		*x = z;

	return 0;
}

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
	if (parse_u8(str, &mac[0]) < 0)
		return -1;
	if (parse_u8(str + 3, &mac[1]) < 0)
		return -1;
	if (parse_u8(str + 6, &mac[2]) < 0)
		return -1;
	if (parse_u8(str + 9, &mac[3]) < 0)
		return -1;
	if (parse_u8(str + 12, &mac[4]) < 0)
		return -1;
	if (parse_u8(str + 15, &mac[5]) < 0)
		return -1;

	return 0;
}

static int write_iface_params(int map_fd, unsigned char *src, unsigned char *dest)
{
	if (bpf_map_update_elem(map_fd, src, dest, 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	printf("forward: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
			src[0], src[1], src[2], src[3], src[4], src[5],
			dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]
	      );

	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

/**
 * @brief 
 * 
 * t setup -n left --legacy-ip
 * t setup -n right --legacy-ip
 * t load -n left -- -F --file xdp_prog_kern_03.o --progsec xdp_redirect_map
 * t load -n right -- -F --file xdp_prog_kern_03.o --progsec xdp_redirect_map
 * 
 * t exec -n left --  ./xdp_loader -d veth0 -F  --file xdp_prog_kern_03.o  --progsec xdp_pass
 * t exec -n right -- ./xdp_loader -d veth0 -F  --file xdp_prog_kern_03.o  --progsec xdp_pass
 * 
 * t redirect right left
 * t redirect left right
 * 
 * ./xdp_stats -d right
 * ./xdp_stats -d left
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */


int main(int argc, char **argv)
{
    //test();

	int i;
	int len;
	int map_fd;
	bool redirect_map;
	char pin_dir[PATH_MAX];
	unsigned char src[ETH_ALEN];
	unsigned char dest[ETH_ALEN];

	struct config cfg = {
		.ifindex   = -1,
		.redirect_ifindex   = -1,
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	redirect_map = (cfg.ifindex > 0) && (cfg.redirect_ifindex > 0);

	if (cfg.redirect_ifindex > 0 && cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	if (parse_mac(cfg.src_mac, src) < 0) {
		fprintf(stderr, "ERR: can't parse mac address %s\n", cfg.src_mac);
		return EXIT_FAIL_OPTION;
	}

	if (parse_mac(cfg.dest_mac, dest) < 0) {
		fprintf(stderr, "ERR: can't parse mac address %s\n", cfg.dest_mac);
		return EXIT_FAIL_OPTION;
	}

	/* Open the tx_port map corresponding to the cfg.ifname interface */
	map_fd = open_bpf_map_file(pin_dir, "tx_port", NULL);
	if (map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	printf("map dir: %s\n", pin_dir);

	if (redirect_map) {
		/* setup a virtual port for the static redirect */
		i = 0;
		bpf_map_update_elem(map_fd, &i, &cfg.redirect_ifindex, 0);
		printf("redirect from ifnum=%d to ifnum=%d\n", cfg.ifindex, cfg.redirect_ifindex);

		/* Open the redirect_params map */
		map_fd = open_bpf_map_file(pin_dir, "redirect_params", NULL);
		if (map_fd < 0) {
			return EXIT_FAIL_BPF;
		}

		/* Setup the mapping containing MAC addresses */
		if (write_iface_params(map_fd, src, dest) < 0) {
			fprintf(stderr, "can't write iface params\n");
			return 1;
		}
	} else {
		/* setup 1-1 mapping for the dynamic router */
		for (i = 1; i < 256; ++i)
			bpf_map_update_elem(map_fd, &i, &i, 0);
	}

	return EXIT_OK;
}



void test()
{
    struct in6_addr addr = {};
    addr.in6_u.u6_addr8[0] =0xfd;
    addr.in6_u.u6_addr8[1] =0xb2;
    addr.in6_u.u6_addr8[2] =0x2c;
    addr.in6_u.u6_addr8[3] =0x26;
    addr.in6_u.u6_addr8[4] =0xf4;
    addr.in6_u.u6_addr8[5] =0xe4;
    addr.in6_u.u6_addr8[6] =0x0;
    addr.in6_u.u6_addr8[7] =0x0; // fdb22c26f4e40000 18280722383279226880

    addr.in6_u.u6_addr8[8] =0xb1;
    addr.in6_u.u6_addr8[9] =0xca;
    addr.in6_u.u6_addr8[10] =0xd2;
    addr.in6_u.u6_addr8[11] =0xd0;
    addr.in6_u.u6_addr8[12] =0xe9;
    addr.in6_u.u6_addr8[13] =0x0f;
    addr.in6_u.u6_addr8[14] =0xf;
    addr.in6_u.u6_addr8[15] =0xf; //  b1cad2d0e90fffff 12811283884713905935

    __u64 u1 = 0;
    __u64 u2 = 0;
    for (int i =  0 ; i < 8 ; i++)
        u1 = u1 << 8 | addr.in6_u.u6_addr8[i];
    for (int i =  8 ; i < 16 ; i++)
        u2 = u2 << 8 | addr.in6_u.u6_addr8[i];
    printf("%llx , %llx \n", u1, u2 );
}
