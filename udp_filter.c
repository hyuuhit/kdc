#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <net/route.h>
#include <asm/atomic.h>

#include "kdc.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hu Yu <huyu@360.cn>");
MODULE_DESCRIPTION("kernel dns cache");

DEFINE_RATELIMIT_STATE(kdc_ratelimit_state, 5 * HZ, 10);

atomic_t route_needed = ATOMIC_INIT(ROUTE_NEEDED);

unsigned short kdc_port = KDC_PORT;

extern kdc_ops_t KDC_OPS;


int kdc_ratelimit(void)
{
    return __ratelimit(&kdc_ratelimit_state);
}

static void calculate_udp_checksum(struct sk_buff *skb, struct net_device *out) {
    struct iphdr    *iph = ip_hdr(skb);
    struct udphdr   *udph = (void *)iph + iph->ihl * 4;

    /* TODO 判断网卡功能，L4校验计算转由硬件 */
    udph->check = 0;
    udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, htons(udph->len), IPPROTO_UDP, csum_partial(udph, htons(udph->len), 0));
    skb->ip_summed = CHECKSUM_NONE;
}

static void send_response(struct sk_buff *skb, struct net_device *in)
{
    struct net *net;
    struct rtable *rt;
    struct flowi fl = {};
    struct iphdr *iph = ip_hdr(skb);

    /* 是否配置为查询路由，是否为环回设备（环回设备的包传递流程不同与普通向外发送） */
    if (atomic_read(&route_needed) || in->flags & IFF_LOOPBACK) {
        net = dev_net(in);
        fl.nl_u.ip4_u.daddr = iph->daddr;
        fl.nl_u.ip4_u.saddr = iph->saddr;
        fl.oif = 0;
        fl.mark = skb->mark;
        fl.flags = 0;
        if (ip_route_output_key(net, &rt, &fl) != 0)  {
            kdc_warn("ip_route_output_key failed");
            kfree_skb(skb);
            return;
        }
        skb_dst_set(skb, &rt->u.dst);

        iph->ttl = dst_metric(skb_dst(skb), RTAX_HOPLIMIT);
        ip_send_check(iph);
        calculate_udp_checksum(skb, skb_dst(skb)->dev);

        dst_output(skb);
    }
    else {
        iph->ttl = IPDEFTTL;
        ip_send_check(iph);
        calculate_udp_checksum(skb, in);
        skb_push(skb, ETH_HLEN);
        skb->dev = in;
        skb->protocol = htons(ETH_P_IP);
        skb->local_df = 1;
        /* skb->pkt_type = PACKET_OUTGOING; */
        dev_queue_xmit(skb);
    }
}

#define VALIDATE_RESPONSE   0
#define VALIDATE_ACCEPT     1
#define VALIDATE_DROP       2

static int validate_in_skb(const struct sk_buff *skb)
{
    struct iphdr    *iph;
    struct udphdr   *udph;
    struct udphdr   buf;

    iph = ip_hdr(skb);

    if (iph->protocol != IPPROTO_UDP)
        return VALIDATE_ACCEPT;

    if (skb->len < (iph->ihl * 4 + sizeof(*udph))) {
        kdc_warn("in udp header lengh: %u, not enough\n", skb->len - iph->ihl * 4);
        return VALIDATE_DROP;
    }

    if (skb_headlen(skb) >= iph->ihl * 4 + sizeof(*udph)) {
        udph = (void *)iph + iph->ihl * 4;
    }
    else {
        skb_copy_bits(skb, iph->ihl * 4, &buf, sizeof(*udph));
        udph = &buf;
    }

    if (ntohs(udph->dest) != kdc_port)
        return VALIDATE_ACCEPT;

    if (ntohs(iph->tot_len) != ntohs(udph->len) + iph->ihl * 4) {
        kdc_warn("in udp packet lengh not match ip packet lengh\n");
        return VALIDATE_DROP;
    }

    /* 假设 DNS 查询包不会超过 MAX_QUERY_LEN */
    if (ntohs(udph->len) > MAX_QUERY_LEN + sizeof(*udph)) {
        kdc_warn("in udp data too large '%lu', from %pI4\n",
                ntohs(udph->len) - sizeof(*udph), &iph->saddr);
        return VALIDATE_DROP;
    }

    return VALIDATE_RESPONSE;
}

static int validate_out_skb(const struct sk_buff *skb)
{
    struct iphdr    *iph;
    struct udphdr   *udph;
    struct udphdr   buf;

    iph = ip_hdr(skb);

    if (iph->protocol != IPPROTO_UDP)
        return VALIDATE_ACCEPT;

    if (skb->len < (iph->ihl * 4 + sizeof(*udph)))
        return VALIDATE_ACCEPT;

    if (skb_headlen(skb) >= iph->ihl * 4 + sizeof(*udph)) {
        udph = (void *)iph + iph->ihl * 4;
    }
    else {
        skb_copy_bits(skb, iph->ihl * 4, &buf, sizeof(*udph));
        udph = &buf;
    }

    if (ntohs(udph->source) != kdc_port)
        return VALIDATE_ACCEPT;

    if (ntohs(iph->tot_len) != ntohs(udph->len) + iph->ihl * 4) {
        kdc_warn("out udp packet lengh not match ip packet lengh\n");
        return VALIDATE_ACCEPT;
    }

    return VALIDATE_RESPONSE;
}

static unsigned int local_in_packet(unsigned int hooknu, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int(*okfn)(struct sk_buff *))
{
    struct sk_buff  *nskb = NULL;
    int             ret;
    int             validate_ret;

    validate_ret = validate_in_skb(skb);

    if (validate_ret == VALIDATE_ACCEPT)
        return NF_ACCEPT;
    else if (validate_ret == VALIDATE_DROP)
        return NF_DROP;


    /*
    kdc_debug("LOCAL_IN ##################################\n");
    kdc_dump_eth_hdr(skb);
    kdc_dump_ip4_hdr(skb);
    kdc_dump_skb(skb);
    kdc_dump_net_device(in);
    kdc_dump_net_device(out);
    */


    if (KDC_OPS.in_filter)
        ret = KDC_OPS.in_filter(&nskb, skb);
    else
        ret = KDC_ACCEPT;

    if (nskb != NULL)
        send_response(nskb, skb->dev);

    return ret;
}

static unsigned int local_out_packet(unsigned int hooknu, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int(*okfn)(struct sk_buff *))
{

    if (validate_out_skb(skb) == VALIDATE_RESPONSE) {
        /*
        kdc_debug("LOCAL_OUT #################################\n");
        kdc_dump_ip4_hdr(skb);
        kdc_dump_skb(skb);
        kdc_dump_net_device(in);
        kdc_dump_net_device(out);
        */

        if (KDC_OPS.out_filter)
            KDC_OPS.out_filter(skb);

    }

    return NF_ACCEPT;
}

static unsigned int post_routing_packet(unsigned int hooknu, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int(*okfn)(struct sk_buff *))
{

    /*
    if (validate_out_skb(skb) == VALIDATE_RESPONSE) {
        kdc_debug("POST_ROUTING ##############################\n");
        kdc_dump_ip4_hdr(skb);
        kdc_dump_skb(skb);
        kdc_dump_net_device(in);
        kdc_dump_net_device(out);
    }
    */
    return NF_ACCEPT;
}

static struct nf_hook_ops filter_test[3] = {
    {
        .hook = local_in_packet,
        .owner = THIS_MODULE,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_LAST,
    },
    {
        .hook = local_out_packet,
        .owner = THIS_MODULE,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_LAST,
    },
    {
        .hook = post_routing_packet,
        .owner = THIS_MODULE,
        .pf = PF_INET,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_LAST,
    },
};

static int __init filter_init(void)
{
    int err;
    if (KDC_OPS.init) {
        err = KDC_OPS.init();
        if (err)
            return err;
    }
    err = nf_register_hooks(filter_test, ARRAY_SIZE(filter_test));
    if (err) {
        if (KDC_OPS.exit)
            KDC_OPS.exit();
        return err;
    }
    return err;
}

static void __exit filter_exit(void)
{
    nf_unregister_hooks(filter_test, ARRAY_SIZE(filter_test));
    if (KDC_OPS.exit) {
        KDC_OPS.exit();
    }
}

module_init(filter_init);
module_exit(filter_exit);
