#ifndef _DNS_CACHE_H
#define _DNS_CACHE_H

struct query_key {
    /* 不区分大小写，全部转换为小写保存 */
    void        *qname;
    uint16_t    qtype;
    uint16_t    qclass;
};

struct query_response {
    void        *cache_use_ptr;
    void        *data;
    uint16_t    *ttl_offset_chain;
    uint16_t    data_len;
    uint16_t    ttl_offset_chain_bytes_len;
    time_t      cache_time;
    time_t      expire_time;
    time_t      last_update_request_time;
};

int dns_cache_init(void);
void dns_cache_destroy(void);
void dns_cache_insert(const struct query_key *key, const struct query_response *response);
struct query_response *dns_cache_find(const struct query_key *query);
void dns_cache_put(const struct query_response *response);

int in_processing_cache(const struct query_key *query);

#endif
