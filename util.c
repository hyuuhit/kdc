#include <linux/kernel.h>
#include <linux/time.h>

#include "kdc.h"

time_t get_cur_time(void)
{
    struct timeval tv;
    do_gettimeofday(&tv);
    return tv.tv_sec;
}

void *kdc_kmalloc(size_t size)
{
    void *ptr = kmalloc(size, GFP_ATOMIC);
    if (ptr == NULL) {
        kdc_warn("memory allocation error\n");
    }
    else {
        kdc_debug("alloc memory addr %p\n", ptr);
    }
    return ptr;
}

void *kdc_kmemdup(const void *src, size_t len)
{
    void *ptr = kmemdup(src, len, GFP_ATOMIC);
    if (ptr == NULL) {
        kdc_warn("memory allocation error\n");
    }
    else {
        kdc_debug("alloc memory addr %p\n", ptr);
    }
    return ptr;
}

void *kdc_kstrdup(const char *s)
{
    void *ptr = kstrdup(s, GFP_ATOMIC);
    if (ptr == NULL) {
        kdc_warn("memory allocation error\n");
    }
    else {
        kdc_debug("alloc memory addr %p\n", ptr);
    }
    return ptr;
}

void kdc_kfree(const void *objp)
{
    kdc_debug("free memory addr %p\n", objp);
    kfree(objp);
}
