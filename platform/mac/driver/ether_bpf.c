#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/file.h>
#include <net/if.h>
#include <net/bpf.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <ifaddrs.h>
#include "platform.h"
#include "util.h"
#include "net.h"
#include "ether.h"

#include "driver/ether_bpf.h"

#include <pthread.h>
#include "pthread_barrier.h"

// for bpf filter
#include <net/ethernet.h>
#include <netinet/if_ether.h>

#define BPF_DEVICE_NUM 4

#define ETHER_BPF_IRQ INTR_IRQ_BASE
// #define ETHER_BPF_IRQ SIGIO

struct ether_bpf {
    char name[IFNAMSIZ];
    int fd;
    unsigned int irq;
};

#define PRIV(x) ((struct ether_bpf *)x->priv)

static char *bpf_buf;
static unsigned int bpf_buf_size;
static int bpf_device_fd;
static struct queue_head bpf_queue;
struct bpf_queue_entry {
    size_t len;
    uint8_t data[]; /* flexible array member */
};
static mutex_t bpf_mutex;

static int
ether_bpf_addr(struct net_device *dev)
{
    // ref. https://field-notes.hatenablog.jp/entry/20101216/1292467817
    struct ifaddrs *ifa_list, *ifa; 
    struct sockaddr_dl *dl; 
    int isSuccessed = -1;
    if (getifaddrs(&ifa_list) < 0) {
        return -1;
    }
    for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) { 
        dl = (struct sockaddr_dl*)ifa->ifa_addr; 
        if (dl->sdl_family == AF_LINK && dl->sdl_type == IFT_ETHER) {
            if (memcmp(PRIV(dev)->name, dl->sdl_data, dl->sdl_nlen) == 0) {
                memcpy(dev->addr, LLADDR(dl), ETHER_ADDR_LEN);
                isSuccessed = 0;
            }
        }
    } 
    freeifaddrs(ifa_list); 
    return isSuccessed;
}

static int
ether_bpf_open(struct net_device *dev)
{
    struct ether_bpf *bpf;
    struct ifreq ifr = {};
    int index, enable = 1;
    char path[16];

    bpf = PRIV(dev);
    // 空いてるBPFデバイスをオープン
    for (index = 0; index < BPF_DEVICE_NUM; index++) {
        snprintf(path, sizeof(path), "/dev/bpf%d", index);
        bpf->fd = open(path, O_RDWR, 0);
        if (bpf->fd != -1) {
            bpf_device_fd = bpf->fd;
            break;
        }
    }
    if (bpf->fd == -1) {
        errorf("open: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    // BPFデバイスにインタフェースを紐付け
    strncpy(ifr.ifr_name, bpf->name, sizeof(ifr.ifr_name)-1);
    if (ioctl(bpf->fd, BIOCSETIF, &ifr) == -1) {
        errorf("ioctl [BIOCSETIF]");
        close(bpf->fd);
        return -1;
    }
    // BPFデバイスの内部バッファのサイズを取得
    if (ioctl(bpf->fd, BIOCGBLEN, &bpf_buf_size) == -1) {
        errorf("ioctl [BIOCGBLEN]");
        close(bpf->fd);
        return -1;
    }
    // 同サイズの受信バッファを動的確保
    bpf_buf = malloc(bpf_buf_size);
    if (!bpf_buf) {
        errorf("malloc failure");
        close(bpf->fd);
        return -1;
    }
    // promiscuous mode
    if (ioctl(bpf->fd, BIOCPROMISC, NULL) == -1) {
        errorf("ioctl [BIOCPROMISC]");
        free(bpf_buf);
        close(bpf->fd);
        return -1;
    }
    // immediate mode
    if (ioctl(bpf->fd, BIOCIMMEDIATE, &enable) == -1) {
        errorf("ioctl [BIOCIMMEDIATE]");
        free(bpf_buf);
        close(bpf->fd);
        return -1;
    }
    // header complete mode
    if (ioctl(bpf->fd, BIOCSHDRCMPLT, &enable) == -1) {
        errorf("ioctl [BIOCSHDRCMPLT]");
        free(bpf_buf);
        close(bpf->fd);
        return -1;
    }

    // ARPのみ許可するBPFフィルタ
    /*
    struct bpf_insn bf_insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ARP, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, sizeof(struct ether_header) + sizeof(struct ether_arp)),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };
    */

    // ARPとETHER_BPF_IP_ADDR(192.168.3.100)へのIPのみ許可するBPFフィルタ
    struct bpf_insn bf_insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ARP, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, sizeof(struct ether_header) + sizeof(struct ether_arp)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 3),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xc0a80364, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    struct bpf_program bprog = {
        sizeof(bf_insns) / sizeof(struct bpf_insn),
        bf_insns
    };
    if (ioctl(bpf->fd, BIOCSETFNR, &bprog) < 0 ) {
        errorf("ioctl [BIOCSETFNR]");
        free(bpf_buf);
        close(bpf->fd);
        return -1;
    }

    /* Set Asynchronous I/O signal delivery destination */
    /* macOSだとbpfデバイスにF_SETOWNやるとinvalid argumentが出てしまうので、
    　　別スレッドでbpfデバイスをpollして待って、そこからシグナルを起こして無理やり繋げます
    if (fcntl(bpf->fd, F_SETOWN, getpid()) == -1) {
        errorf("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
        close(bpf->fd);
        return -1;
    }
    */
    /* Enable Asynchronous I/O */
    /* 上記の理由によってシグナルドリブンIOの設定をする必要がないので、コメントアウトします
    if (fcntl(bpf->fd, F_SETFL, O_ASYNC) == -1) {
        errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
        close(bpf->fd);
        return -1;
    }
    */
    /* Use other signal instead of SIGIO */
    /*
    if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1) {
        errorf("fcntl(F_SETSIG): %s, dev=%s", strerror(errno), dev->name);
        close(bpf->fd);
        return -1;
    }
    */
    
    if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0) {
        if (ether_bpf_addr(dev) == -1) {
            errorf("ether_bpf_addr() failure, dev=%s", dev->name);
            close(bpf->fd);
            return -1;
        }
    }
    return 0;
}

static int
ether_bpf_close(struct net_device *dev)
{
    close(PRIV(dev)->fd);
    return 0;
}

static ssize_t
ether_bpf_write(struct net_device *dev, const uint8_t *frame, size_t flen)
{
    return write(PRIV(dev)->fd, frame, flen);
}

int
ether_bpf_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst)
{
    return ether_transmit_helper(dev, type, buf, len, dst, ether_bpf_write);
}

static ssize_t
ether_bpf_read(struct net_device *dev, uint8_t *buf, size_t size)
{
    ssize_t frame_len;
    struct bpf_hdr *hdr;
    struct bpf_queue_entry *entry;

    mutex_lock(&bpf_mutex);
    entry = queue_pop(&bpf_queue);
    mutex_unlock(&bpf_mutex);
    if (!entry) {
        return -1;
    }
    hdr = (struct bpf_hdr *)(entry->data);
    frame_len = hdr->bh_caplen;

    memcpy(buf, entry->data + hdr->bh_hdrlen, frame_len);
    memory_free(entry);
    return frame_len;
}

static int
ether_bpf_isr(unsigned int irq, void *id)
{
    struct net_device *dev;
    dev = (struct net_device *)id;
    while (bpf_queue.num) {
        ether_input_helper(dev, ether_bpf_read);
    }
    return 0;
}

static struct net_device_ops ether_bpf_ops = {
    .open = ether_bpf_open,
    .close = ether_bpf_close,
    .transmit = ether_bpf_transmit,
};

struct net_device *
ether_bpf_init(const char *name, const char *addr)
{
    struct net_device *dev;
    struct ether_bpf *bpf;

    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    ether_setup_helper(dev);
    if (addr) {
        if (ether_addr_pton(addr, dev->addr) == -1) {
            errorf("invalid address, addr=%s", addr);
            return NULL;
        }
    }
    dev->ops = &ether_bpf_ops;
    bpf = memory_alloc(sizeof(*bpf));
    if (!bpf) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    strncpy(bpf->name, name, sizeof(bpf->name)-1);
    bpf->fd = -1;
    bpf->irq = ETHER_BPF_IRQ;
    dev->priv = bpf;
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        memory_free(bpf);
        return NULL;
    }
    intr_request_irq(bpf->irq, ether_bpf_isr, INTR_IRQ_SHARED, dev->name, dev);
    infof("ethernet device initialized, dev=%s", dev->name);
    return dev;
}

static pthread_t tid;
static pthread_barrier_t barrier;
static volatile sig_atomic_t terminate = 0;

static void
on_signal(int s)
{
    terminate = 1;
}

static void *
ether_bpf_thread(void *arg)
{
    struct pollfd pfd;
    int ret, err;
    sigset_t sigmask;
    struct bpf_hdr *hdr;
    int n, len;
    struct bpf_queue_entry *entry;
    int entry_size = sizeof(*entry);

    pfd.fd = bpf_device_fd;
    pfd.events = POLLIN;
    
    // 元々メインスレッドでSIGHUPをブロックしてintr_threadのsigwaitでSIGHUPを待ち受けるしくみなので、
    // SIGHUPでこのスレッドも止めれるようにSIGHUPをUNBLOCKしておく。(メインスレッドのSIG_BLOCKを引き継いでるから)
    signal(SIGHUP, on_signal);
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);
    err = pthread_sigmask(SIG_UNBLOCK, &sigmask, NULL);
    if (err) {
        errorf("pthread_sigmask() %s", strerror(err));
        return NULL;
    }

    pthread_barrier_wait(&barrier);
    debugf("start");
    while (!terminate) {
        ret = poll(&pfd, 1, -1);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            errorf("poll: %s", strerror(errno));
            return NULL;
        }
        
        //　intr_raise_irqを起こしまくるとうまく動かなかったので、ここでreadした後に次のpollにいく
        n = read(bpf_device_fd, bpf_buf, bpf_buf_size);
        hdr = (struct bpf_hdr *)bpf_buf;
        while ((uintptr_t)hdr < (uintptr_t)bpf_buf + n) {
            // hdr->bh_caplenがEthernetフレームの長さ(Ethernetヘッダ含む。プリアンブルとFCS含まない。)
            len = BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
            entry = memory_alloc(entry_size + len);
            if (!entry) {
                errorf("memory_alloc() failure");
                return NULL;
            }
            entry->len = len;
            memcpy(entry->data, (uint8_t *)hdr, len);
            mutex_lock(&bpf_mutex);
            if (!queue_push(&bpf_queue, entry)) {
                errorf("queue_push() failure");
                memory_free(entry);
                mutex_unlock(&bpf_mutex);
                return NULL;
            }
            mutex_unlock(&bpf_mutex);
            hdr = (struct bpf_hdr *)((uintptr_t)hdr + len);
        }
        intr_raise_irq(ETHER_BPF_IRQ);
    }
    debugf("terminated");
    return NULL;
}

int
ether_bpf_thread_run(void)
{
    tid = pthread_self();
    pthread_barrier_init(&barrier, NULL, 2);
    mutex_init(&bpf_mutex);

    int err;
    err = pthread_create(&tid, NULL, ether_bpf_thread, NULL);
    if (err) {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    pthread_barrier_wait(&barrier);
    debugf("ether_bpf_thread_run");
    return 0;
}

void
ether_bpf_thread_shutdown(void)
{
    if (pthread_equal(tid, pthread_self()) != 0) {
        /* Thread not created */
        return;
    }
    pthread_kill(tid, SIGHUP);
    pthread_join(tid, NULL);
}