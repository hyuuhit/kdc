#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ip.h>

#include "kdc.h"

int create_response_echo_simple(struct sk_buff **nskbp, const struct sk_buff *skb)
{
    struct sk_buff  *nskb;
    struct iphdr    *iph, *niph;
    struct udphdr   *udph, *nudph;
    unsigned char   udp_buf[sizeof(*nudph) + MAX_QUERY_LEN];

    iph = ip_hdr(skb);

    if (skb->data_len) {
        skb_copy_bits(skb, iph->ihl * 4, &udp_buf, ntohs(iph->tot_len) - iph->ihl * 4);
        udph = (struct udphdr *)&udp_buf;
    }
    else {
        udph = (void *)iph + iph->ihl * 4;
    }

    /* TODO 检查L4校验 */

    nskb = alloc_skb(LL_MAX_HEADER + sizeof(*niph) + ntohs(udph->len), GFP_ATOMIC);
    if (!nskb)
        return KDC_ACCEPT;

    skb_reserve(nskb, LL_MAX_HEADER - ETH_HLEN);
    skb_reset_mac_header(nskb);
    memcpy(eth_hdr(nskb)->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);
    memcpy(eth_hdr(nskb)->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);
    eth_hdr(nskb)->h_proto = htons(ETH_P_IP);
    skb_reserve(nskb, ETH_HLEN);

    skb_reset_network_header(nskb);

    niph = (struct iphdr *)skb_put(nskb, sizeof(*niph));
    niph->version   = 4;
    niph->ihl       = sizeof(*niph) / 4;
    niph->tos       = 0;
    niph->id        = 8611;
    niph->frag_off  = htons(IP_DF);
    niph->protocol  = IPPROTO_UDP;
    niph->check     = 0;
    niph->saddr     = iph->daddr;
    niph->daddr     = iph->saddr;

    nudph = (struct udphdr *)skb_put(nskb, ntohs(udph->len));
    memcpy(nudph, udph, ntohs(udph->len));
    swap(nudph->source, nudph->dest);
    nudph->check = 0;

    niph->tot_len = htons(nskb->len);

    *nskbp = nskb;

    /* L4校验在确定发送设备后，再进行计算填充 */

    return KDC_DROP;
}

kdc_ops_t echo_simple_ops = {
    .in_filter = create_response_echo_simple,
    .out_filter = NULL,
    .init = NULL,
    .exit = NULL,
};

