#ifndef _LINUX_NETDEVICE_H
#define _LINUX_NETDEVICE_H

#include "globals.h"
#include <stdint.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>

#define read_lock(LOCK)
#define read_unlock(LOCK)

struct net_device_stats
{
    unsigned long   rx_packets;
    unsigned long   tx_packets;
    unsigned long   rx_bytes;
    unsigned long   tx_bytes;
    unsigned long   rx_errors;
    unsigned long   tx_errors;
    unsigned long   rx_dropped;
    unsigned long   tx_dropped;
};

struct net_device_ops
{
    int (*ndo_open)(struct net_device *dev);
    int (*ndo_stop)(struct net_device *dev);
    int (*ndo_start_xmit)(struct sk_buff *skb, struct net_device *dev);
    struct net_device_stats *(*ndo_get_stats)(struct net_device *dev);
};

struct net_device
{
    char name[IFNAMSIZ];
    int ifindex;
    unsigned short type;
    unsigned char dev_addr[ETH_ALEN];
    int opened;
    int tap_socket;
    const struct net_device_ops *netdev_ops;
    void *private_data;
    unsigned char read_buffer[ETH_DATA_LEN];
};

static inline struct net_device *alloc_netdev(int priv_size, const char *name, void (*setup)(struct net_device *))
{
    struct net_device *r = malloc(sizeof(struct net_device));
    if (!r)
        return NULL;
    memset(r, 0, sizeof(*r));
    strncpy(r->name, name, sizeof(r->name));
    r->tap_socket = -1;
    r->private_data = malloc(priv_size);
    if (priv_size && !r->private_data) {
        free(r);
        return NULL;
    }
    setup(r);
    return r;
}

static inline void ether_setup(struct net_device *netdev)
{
}

static inline struct net_device *make_netdev(struct ifaddrs *a)
{
    if (a->ifa_addr->sa_family != PF_PACKET)
        return NULL;
    struct net_device *r = alloc_netdev(0, a->ifa_name, ether_setup);
    if (!r)
        return NULL;
    memcpy(r->dev_addr, a->ifa_addr->sa_data + 10, ETH_ALEN);
    r->type = ARPHRD_ETHER;
    r->ifindex = if_nametoindex(a->ifa_name);
    return r;
}

#define for_each_netdev(DUMMY, DEV) \
    struct ifaddrs *interfaces, *a; \
    if (getifaddrs(&interfaces) == 0) \
        for (a = interfaces; a || (freeifaddrs(interfaces), 0); a = a->ifa_next) \
            if ((DEV = make_netdev(a)))

static inline void free_netdev(struct net_device *dev)
{
    free(dev->private_data);
    free(dev);
}

static inline void *netdev_priv(const struct net_device *dev)
{
    return dev->private_data;
}

#define NETDEV_TX_OK 0
#define NETDEV_TX_BUSY 1

#define netif_carrier_ok(DEV) 1
#define netif_start_queue(DEV)
#define netif_stop_queue(DEV)
#define netif_wake_queue(DEV)

static inline int register_netdev(struct net_device *dev)
{
    dev->tap_socket = open("/dev/net/tun", O_RDWR);
    if (dev->tap_socket < 0)
        return -errno;
    int flags = fcntl(dev->tap_socket, F_GETFL, 0);
    if (flags < 0
        || fcntl(dev->tap_socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(dev->tap_socket);
        return -errno;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev->name, sizeof(ifr.ifr_name));
    if (ioctl(dev->tap_socket, TUNSETIFF, &ifr) < 0) {
        close(dev->tap_socket);
        return -errno;
    }

    return 0;
}

static inline void unregister_netdev(struct net_device *dev)
{
    if (dev->opened && dev->netdev_ops)
        dev->netdev_ops->ndo_stop(dev);
    dev->opened = 0;
    if (dev->tap_socket >= 0) {
        close(dev->tap_socket);
        dev->tap_socket = -1;
    }
}

/* Unlike actual kernel net devices, this function must be called
   regularly to obtain packets to transmit. */
static inline void netif_run(struct net_device *dev)
{
    if (!dev->netdev_ops || dev->tap_socket < 0)
        return;
    if (!dev->opened) {
        dev->netdev_ops->ndo_open(dev);
        dev->opened = 1;
    }
    ssize_t r = read(dev->tap_socket,dev->read_buffer,sizeof(dev->read_buffer));
    if (r > 0) {
        struct sk_buff *skb = dev_alloc_skb(r);
        memcpy(skb_put(skb, r), dev->read_buffer, r);
        int t = dev->netdev_ops->ndo_start_xmit(skb, dev);
        (void)t;
#if EOE_DEBUG_LEVEL >= 1 && defined(EC_DBG) && defined(__KERNEL__)
        EC_DBG("%s: transmit packet of %zi bytes %s\n", dev->name, r,
            t == NETDEV_TX_OK ? "OK" : "dropped");
#if EOE_DEBUG_LEVEL >= 3
        ec_print_data(dev->read_buffer, r);
#endif
#endif
    }
}

static inline int netif_rx(struct sk_buff *skb)
{
    ssize_t r = write(skb->dev->tap_socket, skb->data, skb->len);
#if EOE_DEBUG_LEVEL >= 1 && defined(EC_DBG) && defined(__KERNEL__)
    EC_DBG("%s: received packet of %zi bytes %s\n", skb->dev->name, r,
        r == skb->len ? "OK" : r > 0 ? "truncated" : "dropped");
#if EOE_DEBUG_LEVEL >= 3
    ec_print_data(skb->data, skb->len);
#endif
#endif
    return r == skb->len ? 0 : -1;
}

struct socket
{
    int fd;
};

#define kvec iovec

static inline int netif_up(struct socket *sock, const char *name)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
    if (ioctl(sock->fd, SIOCGIFFLAGS, &ifr) < 0)
        return -errno;
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock->fd, SIOCSIFFLAGS, &ifr) < 0)
        return -errno;
    return 0;
}

static inline int sock_create_kern(int family, int type, int proto,
                    struct socket **res)
{
    struct socket *r = malloc(sizeof(struct socket));
    if (!r)
        return -ENOMEM;
    r->fd = socket(family, type, proto);
    if (r->fd < 0) {
        printk(KERN_ERR "socket: %s\n", strerror(errno));
        free(r);
        return -errno;
    }
    *res = r;
    return 0;
}

static inline void sock_release(struct socket *sock)
{
    if (!sock)
        return;
    close(sock->fd);
    free(sock);
}

static inline int kernel_bind(struct socket *sock, struct sockaddr *address, socklen_t size)
{
    struct sockaddr_ll *sa = (struct sockaddr_ll *)address;
    sa->sll_hatype = ARPHRD_ETHER;
    sa->sll_pkttype = PACKET_OTHERHOST;
    sa->sll_halen = ETH_ALEN;
    int r = bind(sock->fd, address, size);
    return r < 0 ? -errno : r;
}

static inline int kernel_recvmsg(struct socket *sock, struct msghdr *msg,
                    struct kvec *vec, size_t num, size_t len, int flags)
{
    msg->msg_iov = vec;
    msg->msg_iovlen = num;
    ssize_t r = recvmsg(sock->fd, msg, flags);
    return r < 0 ? -errno : r;
}

static inline int kernel_sendmsg(struct socket *sock, struct msghdr *msg,
                    struct kvec *vec, size_t num, size_t len)
{
    msg->msg_iov = vec;
    msg->msg_iovlen = num;
    ssize_t r = sendmsg(sock->fd, msg, 0);
    return r < 0 ? -errno : r;
}

#endif
