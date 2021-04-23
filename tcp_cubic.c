#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include "tcp_cong.h"

/* BIC TCP Parameters */
struct bictcp {
    u32 cnt;        /* increase cwnd by 1 after ACKs */
    u32 last_max_cwnd;    /* last maximum snd_cwnd */
    u32 last_cwnd;    /* the last snd_cwnd */
    u32 last_time;    /* time when updated last_cwnd */
    u32 bic_origin_point;/* origin point of bic function */
    u32 bic_K;        /* time to origin point
                   from the beginning of the current epoch */
    u32 delay_min;    /* min delay (msec << 3) */
    u32 epoch_start;    /* beginning of an epoch */
    u32 ack_cnt;    /* number of acks */
    u32 tcp_cwnd;    /* estimated tcp cwnd */
    u16 unused;
    u8  sample_cnt;    /* number of samples to decide curr_rtt */
    u8  found;        /* the exit point is found? */
    u32 round_start;    /* beginning of each round */
    u32 end_seq;    /* end_seq of the round */
    u32 last_ack;    /* last time when the ACK spacing is close */
    u32 curr_rtt;    /* the minimum rtt of current round */
};

static void cubic_read(const struct sock *sk, void *cong_data)
{
    memcpy(cong_data, inet_csk_ca(sk),
            min_t(size_t, sizeof(struct bictcp), ICSK_CA_PRIV_SIZE));
}

static int cubic_sprint(char *tbuf,  int n, const void *cc_data) {
    // TODO
    int copied = 0;
    return copied;
}

struct congestion_ops cubic_cong_ops __read_mostly = {
    .read = cubic_read,
    .sprint = cubic_sprint,
};
