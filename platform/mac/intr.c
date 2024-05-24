#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <dispatch/dispatch.h>

#include "platform.h"
#include "pthread_barrier.h"

#include "util.h"
#include "net.h"

struct irq_entry {
    struct irq_entry *next;
    unsigned int irq;
    int (*handler)(unsigned int irq, void *dev);
    int flags;
    char name[16];
    void *dev;
};


static struct irq_entry *irqs;

static sigset_t sigmask;

static pthread_t tid;
static pthread_barrier_t barrier;

struct itimerspec {
    struct timespec  it_interval;  /* Interval for periodic timer */
    struct timespec  it_value;     /* Initial expiration */
};

int
intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev), int flags, const char *name, void *dev)
{
    struct irq_entry *entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
    for (entry = irqs; entry; entry = entry->next) {
        if (entry->irq == irq) {
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
                errorf("conflicts with already registered IRQs");
                return -1;
            }
        }
    }

    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name)-1);
    entry->dev = dev;
    entry->next = irqs;
    irqs = entry;
    sigaddset(&sigmask, irq);
    debugf("registered: irq=%u, name=%s", irq, name);

    return 0;
}

int
intr_raise_irq(unsigned int irq)
{
    return pthread_kill(tid, (int)irq);
}

static void
intr_timer_handler(void *arg)
{
    intr_raise_irq(SIGALRM);
}

static int
intr_timer_setup(struct itimerspec *interval)
{
    if (interval->it_value.tv_sec == 0 && interval->it_value.tv_nsec == 0) {
        return -1;
    }

    dispatch_queue_t queue = dispatch_queue_create("microps.queue", 0);
    dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    dispatch_source_set_event_handler_f(source, intr_timer_handler);

    dispatch_time_t start;
    start = dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * interval->it_value.tv_sec + interval->it_value.tv_nsec);
    dispatch_source_set_timer(source, start, NSEC_PER_SEC * interval->it_value.tv_sec + interval->it_value.tv_nsec, 0);
    dispatch_resume(source);

    return 0;
}

static void *
intr_thread(void *arg)
{
    const struct timespec ts = {0, 1000000}; /* 1ms */
    struct itimerspec interval = {ts, ts};

    int terminate = 0, sig, err;
    struct irq_entry *entry;

    debugf("start");
    pthread_barrier_wait(&barrier);
    if (intr_timer_setup(&interval) == -1) {
        errorf("intr_timer_setup() failure");
        return NULL;
    }
    while (!terminate) {
        err = sigwait(&sigmask, &sig);
        if (err) {
            errorf("sigwait() %s", strerror(err));
            break;
        }
        switch (sig) {
            case SIGHUP:
                terminate = 1;
                break;
            case SIGALRM:
                net_timer_handler();
                break;
            case INTR_IRQ_SOFTIRQ: // ソフトウェア割り込みの処理（プロトコルの処理）
                net_softirq_handler();
                break;
            default: // ハードウェア割り込みの処理（デバイスドライバの処理）
                for (entry = irqs; entry; entry = entry->next) {
                    if (entry->irq == (unsigned int)sig) {
                        debugf("irq=%d, name=%s", entry->irq, entry->name);
                        entry->handler(entry->irq, entry->dev);
                    }
                }
                break;
        }
    }
    debugf("terminated");
    return NULL;
}

int
intr_run(void)
{
    int err;

    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err) {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err) {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    pthread_barrier_wait(&barrier); // intr_threadが準備できるまで待ってる？
    return 0;
}

void
intr_shutdown(void)
{
    if (pthread_equal(tid, pthread_self()) != 0) {
        /* Thread not created */
        return;
    }
    pthread_kill(tid, SIGHUP);
    pthread_join(tid, NULL);
}

int
intr_init(void)
{
    tid = pthread_self();
    pthread_barrier_init(&barrier, NULL, 2);
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);
    sigaddset(&sigmask, SIGUSR1);
    sigaddset(&sigmask, SIGUSR2);
    sigaddset(&sigmask, SIGALRM);
    return 0;
}