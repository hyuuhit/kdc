#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ip.h>

#include "kdc.h"

#ifdef KDC_DEBUG

void kdc_dump_skb(const struct sk_buff *skb) {
    kdc_debug("%-32s: %u\n", "skb->len", skb->len);
    kdc_debug("%-32s: %u\n", "skb->data_len", skb->data_len);
    kdc_debug("%-32s: %hX\n", "skb->protocol", ntohs(skb->protocol));
    kdc_debug("%-32s: %u\n", "skb->pkt_type", skb->pkt_type);
    kdc_debug("%-32s: %u\n", "skb->ip_summed", skb->ip_summed);
    kdc_debug("%-32s: %u\n", "skb->local_df", skb->local_df);
    kdc_debug("%-32s: %u\n", "skb->mark", skb->mark);
    kdc_debug("%-32s: %d\n", "skb->iif", skb->iif);
    kdc_debug("%-32s: %p\n", "skb->head", skb->head);
    kdc_debug("%-32s: %p\n", "skb->data", skb->data);
    kdc_debug("%-32s: %u\n", "skb->tail", skb->tail);
    kdc_debug("%-32s: %u\n", "skb->end", skb->end);

    kdc_debug("%-32s: %p\n", "skb->_skb_dst", skb_dst(skb));
    if (skb_dst(skb)) {
        kdc_debug("%-32s: %p\n", "skb->_skb_dst->dev", skb_dst(skb)->dev);
        if (skb_dst(skb)->dev) {
            kdc_debug("%-32s: %s\n", "skb->_skb_dst->dev->name", skb_dst(skb)->dev->name);
            kdc_debug("%-32s: %u\n", "skb->_skb_dst->dev->refcnt", atomic_read(&skb_dst(skb)->dev->refcnt));
            kdc_debug("%-32s: %hu\n", "skb->_skb_dst->dev->type", skb_dst(skb)->dev->type);
            kdc_debug("%-32s: %hX\n", "skb->_skb_dst->dev->flags", skb_dst(skb)->dev->flags);
        }
    }
    kdc_debug("%-32s: %p\n", "skb->dev", skb->dev);
    if (skb->dev) {
        kdc_debug("%-32s: %s\n", "skb->dev->name", skb->dev->name);
        kdc_debug("%-32s: %u\n", "skb->dev->refcnt", atomic_read(&skb->dev->refcnt));
        kdc_debug("%-32s: %hu\n", "skb->dev->type", skb->dev->type);
        kdc_debug("%-32s: %hX\n", "skb->dev->flags", skb->dev->flags);
    }
}

void kdc_dump_net_device(const struct net_device *dev) {
    kdc_debug("%-32s: %p\n", "dev", dev);
    if(dev) {
        kdc_debug("%-32s: %s\n", "dev->name", dev->name);
        kdc_debug("%-32s: %u\n", "dev->refcnt", atomic_read(&dev->refcnt));
        kdc_debug("%-32s: %hu\n", "dev->type", dev->type);
        kdc_debug("%-32s: %hX\n", "dev->flags", dev->flags);
    }
}

void kdc_dump_eth_hdr(const struct sk_buff *skb) {
    struct ethhdr *h;

    if (skb) {
        h = eth_hdr(skb);
        kdc_debug("L2: %pM --> %pM, proto %hX\n", h->h_source, h->h_dest, ntohs(h->h_proto));
    }
}

void kdc_dump_ip4_hdr(const struct sk_buff *skb) {
    struct iphdr *iph;

    if (skb) {
        iph = ip_hdr(skb);
        kdc_debug("L3: %pI4 --> %pI4, proto %hhu\n", &iph->saddr, &iph->daddr, iph->protocol);
    }
}

#else /* !KDC_DEBUG */

void kdc_dump_skb(const struct sk_buff *skb) {}
void kdc_dump_net_device(const struct net_device *dev) {}
void kdc_dump_eth_hdr(const struct sk_buff *skb) {}
void kdc_dump_ip4_hdr(const struct sk_buff *skb) {}

#endif /* KDC_DEBUG */
