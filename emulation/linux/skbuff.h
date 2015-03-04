#ifndef _LINUX_SK_BUFF_H
#define _LINUX_SK_BUFF_H

#include <stdlib.h>

#define CHECKSUM_UNNECESSARY 1

struct sk_buff
{
    unsigned int        len;
    unsigned char       *head, *data, *tail;
    struct net_device   *dev;
    int                 ip_summed;
    uint16_t            protocol;
};

#define eth_type_trans(SKB, DEV) 0

static inline struct sk_buff *dev_alloc_skb(unsigned int length)
{
    struct sk_buff *buf = malloc(sizeof(struct sk_buff));
    if(!buf)
        return buf;
    buf->len = 0;
    buf->data = buf->head = buf->tail = malloc(length);
    if (!buf->head) {
        free(buf);
        return NULL;
    }
    return buf;
}

static inline void dev_kfree_skb(struct sk_buff *skb)
{
    free(skb->head);
    free(skb);
}

static inline void skb_reserve(struct sk_buff *skb, int len)
{
    skb->data += len;
    skb->tail += len;
}

static inline unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
    skb->data -= len;
    skb->len  += len;
    return skb->data;
}

static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
    unsigned char *tmp = skb->tail;
    skb->tail += len;
    skb->len  += len;
    return tmp;
}

#endif
