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



// ./xdp_loader --dev enp0s5 --force --native-mode --filename xdp_prog_kern_04.o --progsec xdp_patch_watch
// ./xdp_loader --dev enp0s5  --U  --native-mode --force --filename xdp_prog_kern_04.o --progsec xdp_patch_watch
// cat /sys/kernel/debug/tracing/trace_pipe
// ip link set dev enp0s5 xdp off

/*
 * Solution to the assignment 1 in lesson packet02
 */
SEC("xdp_patch_watch")
int xdp_patch_ports_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_proto, ip_proto;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	eth_proto = parse_ethhdr(&nh, data_end, &eth);
	if (eth_proto < 0) {
		action = XDP_ABORTED;
		goto out;
	}

    bpf_printk("srcMAC: %llu, dstMAC: %llu, ethProto: %u",
               ether_addr_to_u64(eth->h_source),
               ether_addr_to_u64(eth->h_dest),
               bpf_ntohs(eth->h_proto));

	if (eth_proto == bpf_htons(ETH_P_IP)) {
		ip_proto = parse_iphdr(&nh, data_end, &iphdr);
        if(iphdr){
            bpf_printk("srcIP4: %u, desIP4: %u",  nh.s_u4_addr, nh.d_u4_addr);
        }
	} else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		ip_proto = parse_ip6hdr(&nh, data_end, &ipv6hdr);
        if(ipv6hdr){
//            bpf_printk("ETH_P_IPV6 protocol s1: %x %x",  nh.s_u6_addr8[0], nh.s_u6_addr8[1]);
//            bpf_printk("ETH_P_IPV6 protocol s2: %x %x",  nh.s_u6_addr8[2], nh.s_u6_addr8[3]);
//            bpf_printk("ETH_P_IPV6 protocol s3: %x %x",  nh.s_u6_addr8[4], nh.s_u6_addr8[5]);
//            bpf_printk("ETH_P_IPV6 protocol s4: %x %x",  nh.s_u6_addr8[6], nh.s_u6_addr8[7]);
//            bpf_printk("ETH_P_IPV6 protocol s5: %x %x",  nh.s_u6_addr8[8], nh.s_u6_addr8[9]);
//            bpf_printk("ETH_P_IPV6 protocol s6: %x %x",  nh.s_u6_addr8[10], nh.s_u6_addr8[11]);
//            bpf_printk("ETH_P_IPV6 protocol s7: %x %x",  nh.s_u6_addr8[12], nh.s_u6_addr8[13]);
//            bpf_printk("ETH_P_IPV6 protocol s8: %x %x",  nh.s_u6_addr8[14], nh.s_u6_addr8[15]);
//
//            bpf_printk("ETH_P_IPV6 protocol d1: %x %x",  nh.d_u6_addr8[0], nh.d_u6_addr8[1]);
//            bpf_printk("ETH_P_IPV6 protocol d2: %x %x",  nh.d_u6_addr8[2], nh.d_u6_addr8[3]);
//            bpf_printk("ETH_P_IPV6 protocol d3: %x %x",  nh.d_u6_addr8[4], nh.d_u6_addr8[5]);
//            bpf_printk("ETH_P_IPV6 protocol d4: %x %x",  nh.d_u6_addr8[6], nh.d_u6_addr8[7]);
//            bpf_printk("ETH_P_IPV6 protocol d5: %x %x",  nh.d_u6_addr8[8], nh.d_u6_addr8[9]);
//            bpf_printk("ETH_P_IPV6 protocol d6: %x %x",  nh.d_u6_addr8[10], nh.d_u6_addr8[11]);
//            bpf_printk("ETH_P_IPV6 protocol d7: %x %x",  nh.d_u6_addr8[12], nh.d_u6_addr8[13]);
//            bpf_printk("ETH_P_IPV6 protocol d8: %x %x",  nh.d_u6_addr8[14], nh.d_u6_addr8[15]);

            bpf_printk("srcIP6: %llx%llx " , ipv6_addr1_to_u64(nh.s_u6_addr8), ipv6_addr2_to_u64(nh.s_u6_addr8));
            bpf_printk("desIP6: %llx%llx " , ipv6_addr1_to_u64(nh.d_u6_addr8), ipv6_addr2_to_u64(nh.d_u6_addr8));
        }
    } else {
		goto out;
	}


	if (ip_proto == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}

        bpf_printk("srcUdpPort: %u, dstUdpPort: %u, ipProto: %u", bpf_ntohs(udphdr->source), bpf_ntohs(udphdr->dest), ip_proto);
		//udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
	} else if (ip_proto == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}

        bpf_printk("srcTcpPort: %u, dstTcpPort: %u, ipProto: %u", bpf_ntohs(tcphdr->source), bpf_ntohs(tcphdr->dest), ip_proto);
		//tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
	} else {
		bpf_printk("otherIPProto: %u ", ip_proto);
	}

out:
    return  action;
    //return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
