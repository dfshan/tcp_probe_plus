#ifndef TCPPROB_TCP_CONG_H
#define TCPPROB_TCP_CONG_H
#include <linux/string.h>

#include "main.h"

struct congestion_ops {
    /* Read CC data */
    void (*read)(const struct sock *sk, void *cong_data);
    /* Print CC data to a buffer */
    int (*sprint)(char *tbuf, int n, const void *cc_data);
};

extern struct congestion_ops cubic_cong_ops;
extern struct congestion_ops bbr_cong_ops;
extern struct congestion_ops cbr_cong_ops;
extern struct congestion_ops bbr2_cong_ops;

static inline void set_cong_ops(struct tcp_hash_flow *tcp_flow, const char *name)
{
    if (strlen(name) == 4 && 0 == strncasecmp(name, "bbr2", 4)) {
        tcp_flow->cong_ops = &bbr2_cong_ops;
    } else if (0 == strncasecmp(name, "bbr", 3)) {
        tcp_flow->cong_ops = &bbr_cong_ops;
    } else if (0 == strncasecmp(name, "cubic", 5)) {
        tcp_flow->cong_ops = &cubic_cong_ops;
    } else {
        pr_warn("tcpprobe_plus: Unsupported congestion control: %s\n", name);
        tcp_flow->cong_ops = NULL;
    }
}
#endif
