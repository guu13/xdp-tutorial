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



// ./xdp_loader --dev enp0s5 --force  --filename xdp_prog_kern_05.o --progsec xdp_patch_modeify_port
// ./xdp_loader --dev enp0s5  --U   --force --filename xdp_prog_kern_05.o --progsec xdp_patch_modeify_port
// cat /sys/kernel/debug/tracing/trace_pipe
// ip link set dev enp0s5 xdp off

/*
 * Solution to the assignment 1 in lesson packet02
 */
SEC("xdp_patch_modeify_port")
int xdp_patch_ports_func(struct xdp_md *ctx)
{
	int eth_proto, ip_proto;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	eth_proto = parse_ethhdr(&nh, data_end, &eth);
	if (eth_proto < 0) {
		return XDP_PASS;
	}

	if (eth_proto != bpf_htons(ETH_P_IP)) 
		return XDP_PASS;

	ip_proto = parse_iphdr(&nh, data_end, &iphdr);
	if (ip_proto != IPPROTO_TCP) 
		return XDP_PASS;
	

	if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) 
		return XDP_PASS;

	if(bpf_ntohs(tcphdr->dest) == 8080)
	{
		bpf_printk("srcTcpPort: %u, dstTcpPort: %u, ipProto: %u", bpf_ntohs(tcphdr->source), bpf_ntohs(tcphdr->dest), ip_proto);
		tcphdr->dest = bpf_htons(8079);
	}	
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
