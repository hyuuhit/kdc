#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <linux/spinlock.h>

#include "kdc.h"
#include "dns_cache.h"
#include "util.h"

#define HASH_SIZE           10240
#define MAX_CACHE_MEM       (2 << 30)

/* 从应用程序响应中捕获的缓存 */
/* TODO false sharing */
struct cache_entry_head {
    spinlock_t          lock;

    struct hlist_head   head;
};

struct cache_entry_node {
    struct query_key        query;
    struct query_response   response;

    struct hlist_node       list;
};

struct dns_cache {
    struct cache_entry_head ct[HASH_SIZE];
} global_cache;
/* END 从应用程序响应中捕获的缓存 */

/* 处理中的查询缓存 */
struct processing_entry_head {
    spinlock_t          lock;
    struct hlist_head   head;
};

struct processing_entry_node {
    struct query_key    query;
    struct hlist_node   list;
    time_t              last_through_time;
};

struct {
    struct processing_entry_head ct[HASH_SIZE];
} global_processing;
/* END 处理中的查询缓存 */

static inline int query_key_cmp(const struct query_key *k1, const struct query_key *k2)
{
    if (k1->qtype == k2->qtype && k1->qclass == k2->qclass
            && strcmp(k1->qname, k2->qname) == 0)
        return 0;
    else
        return 1;
}

unsigned int key_index(const struct query_key *key)
{
    size_t len;
    int i;
    unsigned int hash = 0;

    len = strlen(key->qname);
    for (i = 0; i < len; i++) {
        hash += *((char *)key->qname + i);
    }
    hash %= HASH_SIZE;
    kdc_debug("hash index %u\n", hash);
    return hash;
}


int dns_cache_init(void)
{
    int i;

    kdc_debug("cache init\n");
    for (i = 0; i < HASH_SIZE; i++) {
        spin_lock_init(&global_cache.ct[i].lock);
        INIT_HLIST_HEAD(&global_cache.ct[i].head);
    }

    for (i = 0; i < HASH_SIZE; i++) {
        spin_lock_init(&global_processing.ct[i].lock);
        INIT_HLIST_HEAD(&global_processing.ct[i].head);
    }

    return 0;
}

void dns_cache_destroy(void)
{
    struct hlist_node       *pos;
    struct hlist_node       *n;
    struct cache_entry_node *entry;

    struct processing_entry_node *pentry;
    int                     i;

    kdc_debug("cache destroy\n");

    for (i = 0; i < HASH_SIZE; i++) {
        hlist_for_each_safe(pos, n, &global_cache.ct[i].head) {
            entry = hlist_entry(pos, struct cache_entry_node, list);
            hlist_del(pos);
            kdc_debug("destroy index: %d\n", i);
            if (entry->response.ttl_offset_chain)
                kdc_kfree(entry->response.ttl_offset_chain);
            if (entry->response.data)
                kdc_kfree(entry->response.data);
            if (entry->query.qname)
                kdc_kfree(entry->query.qname);
            kdc_kfree(entry);
        }
    }

    for (i = 0; i < HASH_SIZE; i++) {
        hlist_for_each_safe(pos, n, &global_processing.ct[i].head) {
            pentry = hlist_entry(pos, struct processing_entry_node, list);
            hlist_del(pos);
            kdc_debug("destroy processing index: %d\n", i);
            if (pentry->query.qname)
                kdc_kfree(pentry->query.qname);
            kdc_kfree(pentry);
        }
    }
}

struct query_response *__dns_cache_find(const struct query_key *query_key, unsigned int index)
{
    struct hlist_node *pos;
    struct cache_entry_node *node;
    struct query_key *key;
    hlist_for_each_entry(node, pos, &global_cache.ct[index].head, list) {
        key = &node->query;
        if (query_key->qtype == key->qtype && query_key->qclass == key->qclass
                && strcmp(query_key->qname, key->qname) == 0)
            return &node->response;
    }
    return NULL;
}

struct query_response *dns_cache_find(const struct query_key *query)
{
    struct query_response *response;
    int index = key_index(query);
    spin_lock_bh(&global_cache.ct[index].lock);
    response = __dns_cache_find(query, index);
    if (response == NULL) {
        spin_unlock_bh(&global_cache.ct[index].lock);
    }
    return response;
}

void dns_cache_put(const struct query_response *response)
{
    spin_unlock_bh(&((struct cache_entry_head *)(response->cache_use_ptr))->lock);
}

void dns_cache_insert(const struct query_key *key,
        const struct query_response *response)
{
    struct cache_entry_node __node;
    struct cache_entry_node *node = NULL;
    struct cache_entry_node *new_node = NULL;
    struct query_response *exist_response = NULL;
    unsigned int index;

    index = key_index(key);

    spin_lock_bh(&global_cache.ct[index].lock);

    exist_response = __dns_cache_find(key, index);
    if (exist_response) {
        kdc_debug("cache replace\n");
        memset(&__node, 0, sizeof(__node));
        node = &__node;
        if (response->data) {
            node->response.data = kdc_kmemdup(response->data, response->data_len);
            if (node->response.data == NULL) goto insert_mem_err;
        }
        else {
            node->response.data = NULL;
        }
        if (response->ttl_offset_chain) {
            node->response.ttl_offset_chain = kdc_kmemdup(response->ttl_offset_chain,
                    response->ttl_offset_chain_bytes_len);
            if (node->response.ttl_offset_chain == NULL) goto insert_mem_err;
        }
        else {
            node->response.ttl_offset_chain = NULL;
        }
        if (exist_response->data)
            kdc_kfree(exist_response->data);
        if (exist_response->ttl_offset_chain)
            kdc_kfree(exist_response->ttl_offset_chain);
        exist_response->data = node->response.data;
        exist_response->ttl_offset_chain = node->response.ttl_offset_chain;
        exist_response->data_len = response->data_len;
        exist_response->ttl_offset_chain_bytes_len = response->ttl_offset_chain_bytes_len;
        exist_response->cache_time = response->cache_time;
        exist_response->expire_time = response->expire_time;
        exist_response->last_update_request_time = response->last_update_request_time;
    }
    else {
        kdc_debug("cache create\n");
        new_node = (struct cache_entry_node *)kdc_kmalloc(sizeof(*new_node));
        if (new_node == NULL) goto insert_mem_err;
        memset(new_node, 0, sizeof(*new_node));
        node = new_node;
        node->query.qname = kdc_kstrdup(key->qname);
        if (node->query.qname == NULL) goto insert_mem_err;
        node->query.qtype = key->qtype;
        node->query.qclass = key->qclass;

        /* 这是一段重复代码，头疼 */
        if (response->data) {
            node->response.data = kdc_kmemdup(response->data, response->data_len);
            if (node->response.data == NULL) goto insert_mem_err;
        }
        else {
            node->response.data = NULL;
        }
        if (response->ttl_offset_chain) {
            node->response.ttl_offset_chain = kdc_kmemdup(response->ttl_offset_chain,
                    response->ttl_offset_chain_bytes_len);
            if (node->response.ttl_offset_chain == NULL) goto insert_mem_err;
        }
        else {
            node->response.ttl_offset_chain = NULL;
        }
        /* 重复代码到此为止 */

        node->response.data_len = response->data_len;
        node->response.ttl_offset_chain_bytes_len =response->ttl_offset_chain_bytes_len;
        node->response.cache_time = response->cache_time;
        node->response.expire_time = response->expire_time;
        node->response.last_update_request_time = response->last_update_request_time;

        node->response.cache_use_ptr = &global_cache.ct[index];
        hlist_add_head(&node->list, &global_cache.ct[index].head);
    }
    goto insert_out;

insert_mem_err:
    if (node) {
        if (node->query.qname)
            kdc_kfree(node->query.qname);
        if (node->response.data)
            kdc_kfree(node->response.data);
        if (node->response.ttl_offset_chain)
            kdc_kfree(node->response.ttl_offset_chain);
    }
    if (new_node)
        kdc_kfree(new_node);

insert_out:
    spin_unlock_bh(&global_cache.ct[index].lock);
}

int in_processing_cache(const struct query_key *query)
{
    int ret = 0;
    int index;
    struct hlist_node *pos;
    struct processing_entry_node *node;
    struct query_key *key;
    time_t now;

    now = get_cur_time();
    index = key_index(query);

    spin_lock_bh(&global_processing.ct[index].lock);
    hlist_for_each_entry(node, pos, &global_processing.ct[index].head, list) {
        key = &node->query;
        if (query_key_cmp(key, query) == 0) {
            if (node->last_through_time < now) {
                node->last_through_time = now;
                ret = 0;
            }
            else {
                ret = 1;
            }
            goto processing_cache_out;
        }
    }

    /* 查询未在处理中，插入 */
    if (ret == 0) {
        node = kdc_kmalloc(sizeof(*node));
        if (node == NULL)
            goto processing_cache_out;
        node->query.qname = kdc_kstrdup(query->qname);
        if (node->query.qname == NULL) {
            kdc_kfree(node);
            goto processing_cache_out;
        }
        node->query.qtype = query->qtype;
        node->query.qclass = query->qclass;
        node->last_through_time = now;
        hlist_add_head(&node->list, &global_processing.ct[index].head);
    }

processing_cache_out:
    spin_unlock_bh(&global_processing.ct[index].lock);
    return ret;
}
