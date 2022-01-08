/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"



// ./xdp_loader --dev enp0s5 --force --filename xdp_prog_kern_04.o --progsec xdp_patch_ports
// ./xdp_loader --dev enp0s5  --U --force --filename xdp_prog_kern_04.o --progsec xdp_patch_ports
// cat /sys/kernel/debug/tracing/trace_pipe
// ip link set dev enp0s5 xdp off

/*
 * Solution to the assignment 1 in lesson packet02
 */
SEC("xdp_patch_ports")
int xdp_patch_ports_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

    bpf_printk("srcMAC: %llu, dstMAC: %llu, proto: %u\n",
               ether_addr_to_u64(eth->h_source),
               ether_addr_to_u64(eth->h_dest),
               bpf_ntohs(eth->h_proto));

//    __u32 _iphdr_src ;
//    __u32 _iphdr_des ;
//    int _iphdr_protocol ;
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
//        _iphdr_src = bpf_ntohl(iphdr->saddr);
        bpf_printk("ETH_P_IP protocol: %d\n",  ip_type);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
        //bpf_printk("ETH_P_IPV6 protocol: %d ,  %d\n",  ip_type, sizeof(ipv6hdr->saddr));
//        if(ipv6hdr){
//            __u8 i0 = ipv6hdr->saddr.in6_u.u6_addr8[0];
//            bpf_printk("ETH_P_IPV6 protocol: %u /n",  i0);
//        }
    } else {
		goto out;
	}


	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}

        bpf_printk("IPPROTO_UDP srcPort: %u, dstPort: %u\n", bpf_ntohs(udphdr->source), bpf_ntohs(udphdr->dest));



		//udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}

        bpf_printk("IPPROTO_TCP srcPort: %u, dstPort: %u\n", bpf_ntohs(tcphdr->source), bpf_ntohs(tcphdr->dest));

		//tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
	}

out:
    return  XDP_PASS;
    //return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
