#ifndef _KDC_H
#define _KDC_H

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>

#define KDC_DROP            NF_DROP
#define KDC_ACCEPT          NF_ACCEPT

#define KDC_PORT            53
#define ROUTE_NEEDED        0
#define MAX_QUERY_LEN       512

int kdc_ratelimit(void);

#define kdc_warn(fmt, ...) do { \
    if (kdc_ratelimit()) \
    printk("kdc_warn  cpu:[%02d] " fmt, smp_processor_id(), ##__VA_ARGS__); \
} \
while (0)

#define kdc_bug(c) do { \
    typeof(c) __c = (c); \
    if (__c) kdc_warn("BUG AT [%s:%d], VAL:%d\n", __FILE__, __LINE__, (__c)); \
} \
while (0)

#ifdef KDC_DEBUG
#define kdc_debug(fmt, ...) \
    printk("kdc_debug cpu:[%02d] " fmt, smp_processor_id(), ##__VA_ARGS__)
#else /* !KDC_DEBUG */
#define kdc_debug(...) \
    (void)(0)
#endif /* KDC_DEBUG */

void kdc_dump_skb(const struct sk_buff *skb);
void kdc_dump_net_device(const struct net_device *dev);
void kdc_dump_eth_hdr(const struct sk_buff *skb);
void kdc_dump_ip4_hdr(const struct sk_buff *skb);

typedef struct kdc_ops{
    int     (*in_filter)(struct sk_buff **nskbp, const struct sk_buff *skb);
    void    (*out_filter)(const struct sk_buff *skb);
    int     (*init)(void);
    void    (*exit)(void);
} kdc_ops_t;

#endif /* _KDC_H */
