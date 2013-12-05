#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/ctype.h>

#include "dns_cache.h"
#include "kdc.h"
#include "util.h"

#define RCODE_NOERROR       0
#define RCODE_FORMERR       1
#define ROCDE_SERVFAIL      2
#define RCODE_NXDOMAIN      3
#define RCODE_NOTIMP        4
#define RCODE_REFUSED       5

#define CLASS_IN            1
#define CLASS_CH            3
#define CLASS_ANY           255

#define TYPE_A              1
#define TYPE_NS             2
#define TYPE_MD             3
#define TYPE_MF             4
#define TYPE_CNAME          5
#define TYPE_SOA            6
#define TYPE_MB             7
#define TYPE_MG             8
#define TYPE_MR             9
#define TYPE_NULL           10
#define TYPE_WKS            11
#define TYPE_PTR            12
#define TYPE_HINFO          13
#define TYPE_MINFO          14
#define TYPE_MX             15
#define TYPE_TXT            16
#define TYPE_AAAA           28
#define TYPE_A6             38
#define TYPE_OPT            41
#define TYPE_AXFR           252
#define TYPE_MAILB          253
#define TYPE_MAILA          254
#define TYPE_ANY            255

#define MAX_DOMAIN_LEN      256
#define MAX_RR_NUM          48
#define MIN_TTL             30

/* 小端结构 */
struct dnshdr {
    uint16_t    id;
    uint8_t     rd:1;       /* 要求递归 */
    uint8_t     tc:1;       /* 截断 */
    uint8_t     aa:1;       /* 应答者为授权服务器 */
    uint8_t     opcode:4;   /* 0标准，1反向，2服务器状态，3保留，4通知，5更新 */
    uint8_t     qr:1;       /* 0请求，1应答 */
    uint8_t     rcode:4;    /* 0无错误，1格式错误，2严重错误，3名字错误，4服务器不支持，5拒绝 */
    uint8_t     z:3;        /* 占位0 */
    uint8_t     ra:1;       /* 应答者接受递归 */
    uint16_t    qdcount;    /* 查询数量 */
    uint16_t    ancount;    /* 应答数量 */
    uint16_t    nscount;    /* 应答附带的授权服务器数量 */
    uint16_t    arcount;    /* 应答附带的资源记录数量 */
};

static void print_dnshdr(const struct dnshdr *dnsh);
static const char *type_name(int qtype);
static const char *class_name(int qclass);

/* 解析标准查询，填充查询名、类型、类 */
static int parse_std_query(char *domain,int domain_len, uint16_t *qtype,
        uint16_t *qclass, const struct dnshdr *dnsh, size_t length, int lower);

/* 解析响应包，填充ttl偏移链 */
static int parse_ttl_offset_chain(uint16_t *offset_chain, size_t chain_num,
        uint32_t *min_ttl, const struct dnshdr *dnsh, size_t length);

/* 使用ttl偏移链，修改响应包中的ttl */
static void update_ttl(struct dnshdr *dnsh, const uint16_t *ttl_offset_chain,
        time_t pass);

/* 修改响应包中的qname与查询大小写一致 */
static void update_qname(struct dnshdr *dnsh, const char *qname);

static struct sk_buff *generate_basic_dns_skb(size_t l4_data_len);
static struct sk_buff *generate_formerr_skb(const struct dnshdr *dnsh,
        size_t dns_len);
static struct sk_buff *generate_notimp_skb(const struct dnshdr *dnsh,
        size_t dns_len);
static struct sk_buff *generate_truncated_skb(const struct dnshdr *dnsh,
        size_t dns_len);

/* 查询过滤入口 */
static int  dns_filter_in(struct sk_buff **nskbp, const struct sk_buff *skb);

/* 应用层响应过滤入口 */
static void dns_filter_out(const struct sk_buff *skb);

static int std_cache_handler(struct sk_buff **nskbp, const struct dnshdr *dnsh,
        const struct query_key *key, struct query_response *response);
static int std_query_handler(struct sk_buff **nskbp,
        const struct dnshdr *dnsh, size_t dns_len);
static void std_response_handler(const struct dnshdr *dnsh, int length);


const char *type_name(int qtype)
{
    switch (qtype) {
        case TYPE_A:
            return "A";
        case TYPE_NS:
            return "NS";
        case TYPE_MD:
            return "MD";
        case TYPE_MF:
            return "MF";
        case TYPE_CNAME:
            return "CNAME";
        case TYPE_SOA:
            return "SOA";
        case TYPE_MB:
            return "MB";
        case TYPE_MG: 
            return "MG";
        case TYPE_MR:
            return "MR";
        case TYPE_NULL:
            return "NULL";
        case TYPE_WKS:
            return "WKS";
        case TYPE_PTR:
            return "PTR";
        case TYPE_HINFO:
            return "HINFO";
        case TYPE_MINFO:
            return "MINFO";
        case TYPE_MX:
            return "MX";
        case TYPE_TXT:
            return "TXT";
        case TYPE_AAAA:
            return "AAAA";
        case TYPE_A6:
            return "A6";
        case TYPE_OPT:
            return "OPT";
        case TYPE_AXFR:
            return "AXFR";
        case TYPE_MAILB:
            return "MAILB";
        case TYPE_MAILA:
            return "MAILA";
        case TYPE_ANY:
            return "ANY";
        default:
            return "UNKNOWN";
    }
}

const char *class_name(int qclass)
{
    switch (qclass) {
        case CLASS_IN:
            return "IN";
        case CLASS_CH:
            return "CH";
        case CLASS_ANY:
            return "ANY";
        default:
            return "UNKNOWN";
    }
}

void print_dnshdr(const struct dnshdr *dnsh)
{
    kdc_debug("rd:     %d\n", dnsh->rd);
    kdc_debug("tc:     %d\n", dnsh->tc);
    kdc_debug("aa:     %d\n", dnsh->aa);
    kdc_debug("opcode: %d\n", dnsh->opcode);
    kdc_debug("qr:     %d\n", dnsh->qr);
    kdc_debug("rcode:  %d\n", dnsh->rcode);
    kdc_debug("z:      %d\n", dnsh->z);
    kdc_debug("ra:     %d\n", dnsh->ra);
    kdc_debug("qdcount:%d\n", ntohs(dnsh->qdcount));
    kdc_debug("ancount:%d\n", ntohs(dnsh->ancount));
    kdc_debug("nscount:%d\n", ntohs(dnsh->nscount));
    kdc_debug("arcount:%d\n", ntohs(dnsh->arcount));
}

int parse_std_query(char *domain,int domain_len, uint16_t *qtype, uint16_t *qclass,
        const struct dnshdr *dnsh, size_t packet_len, int lower)
{
    size_t domain_offset = 0;
    size_t packet_offset = sizeof(*dnsh);
    size_t sec_len;
    int i;

    if (ntohs(dnsh->qdcount) != 1 || packet_len <= sizeof(*dnsh))
        return -1;
    if (ntohs(dnsh->qdcount) != 1) {
        kdc_debug("parse query qdcount: %hu\n", ntohs(dnsh->qdcount));
        return -1;
    }
    if (packet_len <= sizeof(*dnsh)) {
        kdc_debug("parse query too short packet_len: %lu\n", packet_len);
        return -1;
    }

    /* TODO 指针方式qname支持 */
    sec_len = *((char *)dnsh + packet_offset);
    while (sec_len != 0) {
        if (domain_offset + sec_len + 1 > domain_len) {
            kdc_debug("parse query domain_offset: %lu, label_len: %lu\n",
                    domain_offset, sec_len);
            return -1;
        }
        if (packet_offset + sec_len + 2 >= packet_len) {
            kdc_debug("pase query packet_offset:%lu, label_len:%lu, packet_len:%lu\n",
                    packet_offset, sec_len, packet_len);
            return -1;
        }
        packet_offset ++;
        for (i = 0; i < sec_len; i++) {
            if (lower)
                domain[domain_offset ++] = tolower(((char *)dnsh)[packet_offset ++]);
            else
                domain[domain_offset ++] = ((char *)dnsh)[packet_offset ++];
        }
        domain[domain_offset ++] = '.';
        sec_len = *((char *)dnsh + packet_offset);
    }

    if (domain_offset <= 0) {
        kdc_debug("parse query empty qname\n");
        return -1;
    }
    domain[domain_offset - 1] = 0;

    if (packet_offset + 4 + 1 > packet_len) {
        kdc_debug("parse query not enough space for type&class, packet_offset:%lu, packet_len:%lu\n", packet_offset, packet_len);
        return -1;
    }

    *qtype = ntohs(*(uint16_t *)((char *)dnsh + packet_offset + 1));
    *qclass = ntohs(*(uint16_t *)((char *)dnsh + packet_offset + 3));

    return 0;
}

struct sk_buff *generate_basic_dns_skb(size_t l4_data_len)
{
    struct sk_buff *skb;
    skb = alloc_skb(LL_MAX_HEADER + sizeof(struct iphdr) + sizeof(struct udphdr) + l4_data_len, GFP_ATOMIC);
    if (skb) {
        skb_reserve(skb, LL_MAX_HEADER + sizeof(struct iphdr) + sizeof(struct udphdr));
    }
    else {
        kdc_warn("generate basic dns skb error\n");
    }
    return skb;
}

struct sk_buff *generate_formerr_skb(const struct dnshdr *dnsh, size_t dns_len)
{
    struct dnshdr *ndnsh;
    struct sk_buff *skb;

    kdc_debug("generate FORMERR skb\n");
    skb = generate_basic_dns_skb(sizeof(struct dnshdr));
    if (skb) {
        ndnsh = (struct dnshdr *)skb_put(skb, sizeof(*ndnsh));
        ndnsh->id = dnsh->id;
        ndnsh->qr = 1;
        ndnsh->opcode = dnsh->opcode;
        ndnsh->aa = 0;
        ndnsh->tc = 0;
        ndnsh->rd = dnsh->rd;
        ndnsh->ra = 1;
        ndnsh->z = 0;
        ndnsh->rcode = RCODE_FORMERR;
        ndnsh->qdcount = htons(0);
        ndnsh->ancount = htons(0);
        ndnsh->nscount = htons(0);
        ndnsh->arcount = htons(0);
    }
    return skb;
}

struct sk_buff *generate_notimp_skb(const struct dnshdr *dnsh, size_t dns_len)
{
    struct dnshdr *ndnsh;
    struct sk_buff *skb;

    kdc_debug("generate NOTIMP skb\n");
    skb = generate_basic_dns_skb(dns_len);
    if (skb) {
        ndnsh = (struct dnshdr *)skb_put(skb, dns_len);
        memcpy(ndnsh, dnsh, dns_len);
        ndnsh->qr = 1;
        ndnsh->aa = 0;
        ndnsh->tc = 0;
        ndnsh->ra = 1;
        ndnsh->z = 0;
        ndnsh->rcode = RCODE_NOTIMP;
    }
    return skb;
}

struct sk_buff *generate_truncated_skb(const struct dnshdr *dnsh, size_t dns_len)
{
    struct dnshdr *ndnsh;
    struct sk_buff *skb;

    kdc_debug("generate TC skb\n");
    skb = generate_basic_dns_skb(dns_len);
    if (skb) {
        ndnsh = (struct dnshdr *)skb_put(skb, dns_len);
        memcpy(ndnsh, dnsh, dns_len);
        ndnsh->qr = 1;
        ndnsh->aa = 0;
        ndnsh->tc = 1;
        ndnsh->ra = 1;
        ndnsh->z = 0;
        ndnsh->rcode = RCODE_NOERROR;
    }
    return skb;
}

void update_ttl(struct dnshdr *dnsh, const uint16_t *ttl_offset_chain, time_t pass)
{
    uint8_t *p8 = (uint8_t *)dnsh;
    int     i = 0;
    time_t  ttl;

    if (ttl_offset_chain == NULL)
        return;

    while (ttl_offset_chain[i]) {
        ttl = ntohl(*(uint32_t *)(p8 + ttl_offset_chain[i]));
        if (ttl < pass)
            *(uint32_t *)(p8 + ttl_offset_chain[i]) = htonl(0);
        else
            *(uint32_t *)(p8 + ttl_offset_chain[i]) = htonl(ttl - pass);
        i ++;
    }
}

void update_qname(struct dnshdr *dnsh, const char *qname)
{
    char *p = (char *)dnsh + sizeof(*dnsh);
    int len;
    
    len = *p;
    p ++;
    while (len) {
        memcpy(p, qname, len);
        p += len;
        qname += len;
        len = *p;
        p ++;
        qname ++;
    }
    return;
}

/* TODO 未完*/
int std_cache_handler(struct sk_buff **nskbp, const struct dnshdr *dnsh,
        const struct query_key *key, struct query_response *response)
{
    struct dnshdr   *ndnsh;
    time_t          now;

    now = get_cur_time();

    if (response->data == NULL) {
        if (response->data_len == RCODE_NXDOMAIN || response->data_len == RCODE_NOTIMP) {
            *nskbp = generate_basic_dns_skb(sizeof(*dnsh) + strlen(key->qname) + 6);

            if (*nskbp == NULL)
                return KDC_ACCEPT;

            ndnsh = (struct dnshdr *)skb_put(*nskbp,
                    sizeof(*dnsh) + strlen(key->qname) + 6);
            memcpy(ndnsh, dnsh, sizeof(*ndnsh) + strlen(key->qname) + 6);
            ndnsh->tc = 0;
            ndnsh->aa = 0;
            ndnsh->qr = 1;
            ndnsh->rcode = response->data_len;
            ndnsh->z = 0;
            ndnsh->ra = 1;
            ndnsh->qdcount = htons(1);
            ndnsh->ancount = htons(0);
            ndnsh->nscount = htons(0);
            ndnsh->arcount = htons(0);
        }
        else {
            /* 不应当进入这里 */
            kdc_bug(1);
        }
    }
    else {
        *nskbp = generate_basic_dns_skb(response->data_len);
        if (*nskbp == NULL)
            return KDC_ACCEPT;
        ndnsh = (struct dnshdr *)skb_put(*nskbp, response->data_len);
        memcpy(ndnsh, response->data, response->data_len);
        update_ttl(ndnsh, response->ttl_offset_chain, now - response->cache_time);
        update_qname(ndnsh, key->qname);
    }

    /* 限制过期缓存穿透速率 */
    if (*nskbp && (response->expire_time > now ||
                response->last_update_request_time >= get_cur_time() - 1)) {
        kdc_debug("response created\n");
        return KDC_DROP;
    }
    else if (*nskbp) {
        kdc_debug("response created (ttl expire)\n");
        response->last_update_request_time = get_cur_time();
        return KDC_ACCEPT;
    }
    else {
        kdc_bug(1);
        return KDC_ACCEPT;
    }
}

int std_query_handler(struct sk_buff **nskbp,
        const struct dnshdr *dnsh, size_t dns_len)
{

    struct query_key key;
    struct query_response *response;
    /* TODO 减少栈空间使用，注意false sharing */
    char domain[MAX_DOMAIN_LEN];
    char low_case_domain[MAX_DOMAIN_LEN];
    int err;
    int i;

    err = parse_std_query(domain, sizeof(domain),
            &key.qtype, &key.qclass, dnsh, dns_len, 0);
    if (err) {
        kdc_debug("query parse failed\n");
        *nskbp = generate_formerr_skb(dnsh, dns_len);
        return KDC_DROP;
    }

    kdc_debug("std query '%s %s %s'\n", domain,
            type_name(key.qtype), class_name(key.qclass));

    /* 转换为小写再查询 */
    i = 0;
    do {
        low_case_domain[i] = tolower(domain[i]);
    } while (domain[i++] != 0);

    key.qname = &low_case_domain;
    response = dns_cache_find(&key);

    if (response != NULL) {
        int ret;
        kdc_debug("query is cached\n");
        /* 生成响应时，确保响应包中大小写与查询相同 */
        key.qname = &domain;
        ret = std_cache_handler(nskbp, dnsh, &key, response);
        dns_cache_put(response);
        return ret;
    }
    else if (in_processing_cache(&key)) {
        /* 已经有相同查询穿透过，系统处理中 */
        kdc_debug("query is processing\n");
        return KDC_DROP;
    }
    else {
        /* TODO 未缓存查询也应当限制穿透速率 */
        kdc_debug("query isn't cached\n");
        return KDC_ACCEPT;
    }
}

int dns_filter_in(struct sk_buff **nskbp, const struct sk_buff *skb)
{
    int             ret_code;
    struct sk_buff  *nskb = NULL;
    struct iphdr    *iph, *niph;
    struct udphdr   *udph, *nudph;
    struct dnshdr   *dnsh, *ndnsh;
    uint16_t        dns_len;
    /* TODO 减少栈空间使用 */
    unsigned char   udp_buf[sizeof(*udph) + MAX_QUERY_LEN];


    kdc_debug("in dns filter\n");

    iph = ip_hdr(skb);

    if (skb->data_len) {
        skb_copy_bits(skb, ip_hdrlen(skb), &udp_buf, ntohs(iph->tot_len) - ip_hdrlen(skb));
        udph = (struct udphdr *)&udp_buf;
    }
    else {
        udph = (void *)iph + ip_hdrlen(skb);
    }

    /* TODO 检查L4校验 */

    dnsh = (void *)udph + sizeof(*udph);
    dns_len = ntohs(udph->len) - sizeof(*udph);

    if (dns_len < sizeof(*dnsh)) {
        kdc_debug("incomplete dnshdr\n");
        return KDC_DROP;
    }

    if (dnsh->qr != 0 || dnsh->rd != 1) {
        /* 要求请求类型、要求递归 */
        kdc_debug("qr: %u, rd: %u\n", dnsh->qr, dnsh->rd);
        nskb = generate_formerr_skb(dnsh, dns_len);
        ret_code = KDC_DROP;
    }
    else if (dnsh->opcode != 0 || ntohs(dnsh->qdcount) != 1 || ntohs(dnsh->arcount) != 0) {
        /* 要求标准查询、查询段数量1、附件段数量0 */
        kdc_debug("opcode: %u, qdcount: %u, arcount: %u\n", dnsh->opcode,
                ntohs(dnsh->qdcount), ntohs(dnsh->arcount));
        nskb = generate_notimp_skb(dnsh, dns_len);
        ret_code = KDC_DROP;
    }
    else {
        /* 符合要求的查询，开始查找缓存 */
        ret_code = std_query_handler(&nskb, dnsh, dns_len);
    }

    /* 检查是否有新skb生成，若有则设置查询ID并填充L4&L3&L2头 */
    if (nskb) {
        nudph = (struct udphdr *)skb_push(nskb, sizeof(*nudph));
        skb_reset_transport_header(nskb);
        ndnsh = (struct dnshdr *)((char *)nudph + sizeof(*nudph));
        ndnsh->id       = dnsh->id;
        nudph->check    = 0;
        nudph->len      = htons(nskb->len);
        nudph->source   = udph->dest;
        nudph->dest     = udph->source;

        niph = (struct iphdr *)skb_push(nskb, sizeof(*niph));
        skb_reset_network_header(nskb);
        niph->version   = 4;
        niph->ihl       = sizeof(*niph) / 4;
        niph->tos       = 0;
        niph->id        = 8611;
        niph->frag_off  = htons(IP_DF);
        niph->protocol  = IPPROTO_UDP;
        niph->check     = 0;
        niph->saddr     = iph->daddr;
        niph->daddr     = iph->saddr;
        niph->tot_len   = htons(nskb->len);

        skb_push(nskb, ETH_HLEN);
        skb_reset_mac_header(nskb);
        skb_reserve(nskb, ETH_HLEN);
        memcpy(eth_hdr(nskb)->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);
        memcpy(eth_hdr(nskb)->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);
        eth_hdr(nskb)->h_proto = htons(ETH_P_IP);

        *nskbp = nskb;
    }
    return ret_code;
}

int parse_ttl_offset_chain(uint16_t *offset_chain, size_t chain_num,
        uint32_t *min_ttl, const struct dnshdr *dnsh, size_t length)
{
    size_t  slot = 0;
    size_t  rr_num;
    size_t  offset;
    size_t  label_len;
    size_t  rr_data_len;

    uint8_t *p8;

    rr_num = ntohs(dnsh->ancount) + ntohs(dnsh->nscount) + ntohs(dnsh->arcount);

    p8 = (uint8_t *)dnsh;
    offset = sizeof(*dnsh);
    label_len = *(p8 + offset);
    while (label_len) {
        offset += label_len + 1;
        label_len = *(p8 + offset);
    }
    offset += 5;
    *min_ttl = 0;
    while (slot < chain_num && slot < rr_num && offset < length) {
        label_len = *(p8 + offset);
        while (label_len) {
            if ((label_len & 192) == 192) {
                /* 压缩类型 */
                offset += 6;
                if (offset >= length)
                    return -1;
                break;
            }
            else if (label_len > 63) {
                /* 不合法 */
                return -1;
            }
            else {
                offset += label_len + 1;
                if (offset >= length)
                    return -1;
                label_len = *(p8 + offset);
            }
        }
        if (slot == 0) {
            *min_ttl = ntohl(*(uint32_t *)(p8 + offset));
        }
        else if (*min_ttl > ntohl(*(uint32_t *)(p8 + offset))) {
            *min_ttl = ntohl(*(uint32_t *)(p8 + offset));
        }
        offset_chain[slot++] = offset;
        offset += 4;
        if (offset >= length)
            return -1;
        rr_data_len = ntohs(*(uint16_t *)(p8 + offset));
        offset += 2 + rr_data_len;
    }
    if (slot != rr_num || offset != length) {
        return -1;
    }
    else {
        return slot;
    }
}

void std_response_handler(const struct dnshdr *dnsh, int length)
{
    struct      query_key key;
    struct      query_response response;
    /* TODO 减少栈空间使用，注意false sharing */
    char        low_case_domain[MAX_DOMAIN_LEN];
    uint16_t    offset_chain[MAX_RR_NUM + 1];
    int         err;

    key.qname = &low_case_domain;

     /* 格式错误应在交由应用程序前拦截并响应 */
     /* 严重错误与拒绝暂不缓存 */
    if (dnsh->rcode != RCODE_NOERROR && dnsh->rcode != RCODE_NXDOMAIN && dnsh->rcode != RCODE_NOTIMP)
        return;

    err = parse_std_query(low_case_domain, sizeof(low_case_domain),
            &key.qtype, &key.qclass, dnsh, length, 1);
    if (err) {
        kdc_warn("response parse query failed\n");
        return;
    }

    kdc_debug("std response '%s %s %s'\n", low_case_domain,
            type_name(key.qtype), class_name(key.qclass));

    memset(&response, 0, sizeof(response));

    if (dnsh->rcode == RCODE_NOERROR) {
        int         ttl_ret;
        uint32_t    min_ttl = 0;

        ttl_ret = parse_ttl_offset_chain(offset_chain, MAX_RR_NUM, &min_ttl, dnsh, length);
        if (ttl_ret < 0) {
            min_ttl = MIN_TTL;
            response.ttl_offset_chain = NULL;
            response.ttl_offset_chain_bytes_len = 0;
            kdc_warn("ttl parse error (%s %s %s)\n",
                    low_case_domain, type_name(key.qtype), class_name(key.qclass));
        }
        else if (ttl_ret == 0) {
            min_ttl = MIN_TTL;
            response.ttl_offset_chain = NULL;
            response.ttl_offset_chain_bytes_len = 0;
            kdc_debug("ttl parse slot %d, MIN_TTL %d\n", ttl_ret, MIN_TTL);
        }
        else {
            if (min_ttl < MIN_TTL) {
                kdc_debug("ttl parse slot %d, min_ttl %u (least %d)\n",
                        ttl_ret, min_ttl, MIN_TTL);
                min_ttl = MIN_TTL;
            }
            else {
                kdc_debug("ttl parse slot %d, min_ttl %u\n", ttl_ret, min_ttl);
            }
            offset_chain[ttl_ret] = 0;
            response.ttl_offset_chain = offset_chain;
            response.ttl_offset_chain_bytes_len = sizeof(offset_chain[0]) * (ttl_ret + 1);
        }

        response.data = (void *)dnsh;
        response.data_len = length;
        response.cache_time = get_cur_time();
        response.expire_time = response.cache_time + min_ttl;
        response.last_update_request_time = response.cache_time;
    }
    else if (dnsh->rcode == RCODE_NXDOMAIN || dnsh->rcode == RCODE_NOTIMP) {
        /* 域名不存在 or 服务器不支持 */
        response.data = NULL;
        response.data_len = dnsh->rcode;
        response.cache_time  = get_cur_time();
        response.expire_time = response.cache_time + MIN_TTL;
        response.last_update_request_time = response.cache_time;
    }
    else {
        kdc_bug(1);
        return;
    }

    dns_cache_insert(&key, &response);
}

void dns_filter_out(const struct sk_buff *skb)
{
    struct iphdr    *iph;
    struct udphdr   *udph;
    struct dnshdr   *dnsh;
    int             udp_len;
    int             response_len;
    int             offset;
    unsigned char   udp_buf[sizeof(*udph) + MAX_QUERY_LEN];

    kdc_debug("out dns filter\n");

    iph = ip_hdr(skb);

    if (likely(!skb_is_nonlinear(skb))) {
        udph = (void *)iph + ip_hdrlen(skb);
    }
    else if (skb->len <= sizeof(*udph) + MAX_QUERY_LEN + ip_hdrlen(skb)) {
        skb_copy_bits(skb, ip_hdrlen(skb), &udp_buf, ntohs(iph->tot_len) - ip_hdrlen(skb));
        udph = (struct udphdr *)&udp_buf;
    }
    else {
        kdc_warn("response is nonlinear and len '%u'\n", skb->len);
        return;
    }

    udp_len = ntohs(udph->len);

    if (udp_len < sizeof(*udph) + sizeof(*dnsh)) {
        kdc_warn("response length %hu too short, %pI4 -> %pI4\n", udp_len, &iph->saddr, &iph->daddr);
        return;
    }

    dnsh = (void *)udph + sizeof(*udph);
    response_len = udp_len - sizeof(*udph);
    offset = 0;

    if (dnsh->opcode == 0) {
        /* 域名解析请求的响应 */
        std_response_handler(dnsh, response_len);
    }
    else {
        /* 其他类型不支持 */
        kdc_warn("opcode %d not supported in response\n", dnsh->opcode);
    }
}

struct kdc_ops dns_filter_ops = {
    .in_filter = dns_filter_in,
    .out_filter = dns_filter_out,
    .init = dns_cache_init,
    .exit = dns_cache_destroy,
};
