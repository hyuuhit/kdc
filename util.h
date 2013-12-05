#ifndef _UTIL_H
#define _UTIL_H

time_t get_cur_time(void);

void *kdc_kmalloc(size_t size);
void *kdc_kmemdup(const void *src, size_t len);
void *kdc_kstrdup(const char *s);
void kdc_kfree(const void *objp);

#endif
