#include <linux/module.h>
#include <linux/list.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/win_minmax.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include "tcp_cong.h"

/* BBR congestion control block */
struct bbr {
    u32 min_rtt_us;            /* min RTT in min_rtt_win_sec window */
    u32 min_rtt_stamp;            /* timestamp of min_rtt_us */
    u32 probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
    struct minmax bw;    /* Max recent delivery rate in pkts/uS << 24 */
    u32 rtt_cnt;        /* count of packet-timed rounds elapsed */
    u32 next_rtt_delivered; /* scb->tx.delivered at end of round */
    u64 cycle_mstamp;         /* time of this cycle phase start */
    u32 mode:3,             /* current bbr_mode in state machine */
        prev_ca_state:3,     /* CA state on previous ACK */
        packet_conservation:1,  /* use packet conservation? */
        restore_cwnd:1,         /* decided to revert cwnd to old value */
        round_start:1,         /* start of packet-timed tx->ack round? */
        tso_segs_goal:7,     /* segments we want in each skb we send */
        idle_restart:1,         /* restarting after idle? */
        probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
        unused:5,
        lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
        lt_rtt_cnt:7,         /* round trips in long-term interval */
        lt_use_bw:1;         /* use lt_bw as our bw estimate? */
    u32 lt_bw;             /* LT est delivery rate in pkts/uS << 24 */
    u32 lt_last_delivered;   /* LT intvl start: tp->delivered */
    u32 lt_last_stamp;         /* LT intvl start: tp->delivered_mstamp */
    u32 lt_last_lost;         /* LT intvl start: tp->lost */
    u32 pacing_gain:10,    /* current gain for setting pacing rate */
        cwnd_gain:10,    /* current gain for setting cwnd */
        full_bw_reached:1,   /* reached full bw in Startup? */
        full_bw_cnt:2,    /* number of rounds without large bw gains */
        cycle_idx:3,    /* current index in pacing_gain cycle array */
        has_seen_rtt:1, /* have we seen an RTT sample yet? */
        unused_b:5;
    u32 prior_cwnd;    /* prior cwnd upon entering loss recovery */
    u32 full_bw;    /* recent bw, to estimate if pipe is full */
    u64 maxbw_Bps;
    u32 lt_bw_Bps;
};

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
#define BW_SCALE 24
static u64 bbr_rate_bytes_per_sec(const struct sock *sk, u64 rate)
{
    rate *= tcp_sk(sk)->mss_cache;
    rate *= USEC_PER_SEC;
    return rate >> BW_SCALE;
}

/*static u64 bbr_rate_bps(struct sock *sk, u64 rate)
{
    rate *= tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache);
    rate *= USEC_PER_SEC;
    rate = (rate >> BW_SCALE) << 3;
    return rate;
}*/

static void bbr_read(const struct sock *sk, void *cong_data)
{
    struct bbr *ca = inet_csk_ca(sk);
    memcpy(cong_data, ca, min_t(size_t, sizeof(struct bbr), ICSK_CA_PRIV_SIZE));
    ca->maxbw_Bps = bbr_rate_bytes_per_sec(sk, minmax_get(&ca->bw));
    ca->lt_bw_Bps = bbr_rate_bytes_per_sec(sk, ca->lt_bw);
}

static int bbr_sprint(char *tbuf,  int n, const void *cong_data) {
    int copied = 0;
    struct bbr *ca = (struct bbr *) cong_data;
    copied += scnprintf(tbuf+copied, n-copied, " %llu %u", ca->maxbw_Bps, ca->pacing_gain);
    copied += scnprintf(tbuf+copied, n-copied, " %u", ca->min_rtt_us);
    copied += scnprintf(tbuf+copied, n-copied, " %u %u", ca->round_start, ca->rtt_cnt);
    copied += scnprintf(tbuf+copied, n-copied, " %u %u", ca->mode, ca->cycle_idx);
    copied += scnprintf(tbuf+copied, n-copied, " %u %u", ca->lt_is_sampling, ca->lt_rtt_cnt);
    copied += scnprintf(tbuf+copied, n-copied, " %u %u", ca->lt_use_bw, ca->lt_bw_Bps);
    return copied;
}

struct congestion_ops bbr_cong_ops __read_mostly = {
    .read = bbr_read,
    .sprint = bbr_sprint,
};
