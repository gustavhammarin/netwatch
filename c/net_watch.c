//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u8 protocol;
    __u16 dst_port;
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
};
#define ETH_P_IP    0x0800

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_counts SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;
    key.dst_port = 0;

    void *transport = (void *)ip + (ip->ihl * 4);
    if (transport > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        key.dst_port = bpf_ntohs(tcp->dest);
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        key.dst_port = bpf_ntohs(udp->dest);
    }

    __u64 packet_size = data_end - data;

    struct flow_value *value = bpf_map_lookup_elem(&flow_counts, &key);

    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, packet_size);
    } else {
        struct flow_value initial = {
            .packets = 1,
            .bytes = packet_size,
        };
        bpf_map_update_elem(&flow_counts, &key, &initial, BPF_ANY);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";