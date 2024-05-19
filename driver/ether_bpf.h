#ifndef ETHER_BPF_H
#define ETHER_BPF_H

#include "net.h"

extern struct net_device *
ether_bpf_init(const char *name, const char *addr);

extern int
ether_bpf_thread_run(void);

extern void
ether_bpf_thread_shutdown(void);

#endif