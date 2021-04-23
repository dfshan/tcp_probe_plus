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


/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8    /* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

#define FLAG_DEBUG_VERBOSE    0x1    /* Verbose debugging messages */
#define FLAG_DEBUG_LOOPBACK    0x2    /* Do NOT skip loopback addr */

#define CYCLE_LEN        8    /* number of phases in a pacing gain cycle */

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode {
    BBR_STARTUP,    /* ramp up sending rate rapidly to fill pipe */
    BBR_DRAIN,    /* drain any queue created during startup */
    BBR_PROBE_BW,    /* discover, share bw: pace around estimated bw */
    BBR_PROBE_RTT,    /* cut inflight to min to probe min_rtt */
};

/* How does the incoming ACK stream relate to our bandwidth probing? */
enum bbr_ack_phase {
    BBR_ACKS_INIT,          /* not probing; not getting probe feedback */
    BBR_ACKS_REFILLING,      /* sending at est. bw to fill pipe */
    BBR_ACKS_PROBE_STARTING,  /* inflight rising to probe bw */
    BBR_ACKS_PROBE_FEEDBACK,  /* getting feedback from bw probing */
    BBR_ACKS_PROBE_STOPPING,  /* stopped probing; still getting feedback */
};

/* BBR congestion control block */
struct bbr {
    u32 min_rtt_us;            /* min RTT in min_rtt_win_sec window */
    u32 min_rtt_stamp;            /* timestamp of min_rtt_us */
    u32 probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
    u32 probe_rtt_min_us;    /* min RTT in bbr_probe_rtt_win_ms window */
    u32 probe_rtt_min_stamp;    /* timestamp of probe_rtt_min_us*/
    u32 next_rtt_delivered; /* scb->tx.delivered at end of round */
    u32 prior_rcv_nxt;    /* tp->rcv_nxt when CE state last changed */
    u64 cycle_mstamp;         /* time of this cycle phase start */
    u32 mode:3,             /* current bbr_mode in state machine */
        prev_ca_state:3,     /* CA state on previous ACK */
        packet_conservation:1,  /* use packet conservation? */
        round_start:1,         /* start of packet-timed tx->ack round? */
        ce_state:1,          /* If most recent data has CE bit set */
        bw_probe_up_rounds:5,   /* cwnd-limited rounds in PROBE_UP */
        try_fast_path:1,     /* can we take fast path? */
        unused2:11,
        idle_restart:1,         /* restarting after idle? */
        probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
        cycle_idx:3,    /* current index in pacing_gain cycle array */
        has_seen_rtt:1;         /* have we seen an RTT sample yet? */
    u32 pacing_gain:11,    /* current gain for setting pacing rate */
        cwnd_gain:11,    /* current gain for setting cwnd */
        full_bw_reached:1,   /* reached full bw in Startup? */
        full_bw_cnt:2,    /* number of rounds without large bw gains */
        init_cwnd:7;    /* initial cwnd */
    u32 prior_cwnd;    /* prior cwnd upon entering loss recovery */
    u32 full_bw;    /* recent bw, to estimate if pipe is full */

    /* For tracking ACK aggregation: */
    u64 ack_epoch_mstamp;    /* start of ACK sampling epoch */
    u16 extra_acked[2];        /* max excess data ACKed in epoch */
    u32 ack_epoch_acked:20,    /* packets (S)ACKed in sampling epoch */
        extra_acked_win_rtts:5,    /* age of extra_acked, in round trips */
        extra_acked_win_idx:1,    /* current index in extra_acked array */
    /* BBR v2 state: */
        unused1:2,
        startup_ecn_rounds:2,    /* consecutive hi ECN STARTUP rounds */
        loss_in_cycle:1,    /* packet loss in this cycle? */
        ecn_in_cycle:1;        /* ECN in this cycle? */
    u32 loss_round_delivered; /* scb->tx.delivered ending loss round */
    u32 undo_bw_lo;         /* bw_lo before latest losses */
    u32 undo_inflight_lo;    /* inflight_lo before latest losses */
    u32 undo_inflight_hi;    /* inflight_hi before latest losses */
    u32 bw_latest;     /* max delivered bw in last round trip */
    u32 bw_lo;         /* lower bound on sending bandwidth */
    u32 bw_hi[2];     /* upper bound of sending bandwidth range*/
    u32 inflight_latest; /* max delivered data in last round trip */
    u32 inflight_lo;     /* lower bound of inflight data range */
    u32 inflight_hi;     /* upper bound of inflight data range */
    u32 bw_probe_up_cnt; /* packets delivered per inflight_hi incr */
    u32 bw_probe_up_acks;  /* packets (S)ACKed since inflight_hi incr */
    u32 probe_wait_us;     /* PROBE_DOWN until next clock-driven probe */
    u32 ecn_eligible:1,    /* sender can use ECN (RTT, handshake)? */
        ecn_alpha:9,    /* EWMA delivered_ce/delivered; 0..256 */
        bw_probe_samples:1,    /* rate samples reflect bw probing? */
        prev_probe_too_high:1, /* did last PROBE_UP go too high? */
        stopped_risky_probe:1, /* last PROBE_UP stopped due to risk? */
        rounds_since_probe:8,  /* packet-timed rounds since probed bw */
        loss_round_start:1,    /* loss_round_delivered round trip? */
        loss_in_round:1,       /* loss marked in this round trip? */
        ecn_in_round:1,           /* ECN marked in this round trip? */
        ack_phase:3,           /* bbr_ack_phase: meaning of ACKs */
        loss_events_in_round:4,/* losses in STARTUP round */
        initialized:1;           /* has bbr_init() been called? */
    u32 alpha_last_delivered;     /* tp->delivered    at alpha update */
    u32 alpha_last_delivered_ce; /* tp->delivered_ce at alpha update */

    /* Params configurable using setsockopt. Refer to correspoding
     * module param for detailed description of params.
     */
    struct bbr_params {
        u32 high_gain:11,        /* max allowed value: 2047 */
            drain_gain:10,        /* max allowed value: 1023 */
            cwnd_gain:11;        /* max allowed value: 2047 */
        u32 cwnd_min_target:4,    /* max allowed value: 15 */
            min_rtt_win_sec:5,    /* max allowed value: 31 */
            probe_rtt_mode_ms:9,    /* max allowed value: 511 */
            full_bw_cnt:3,        /* max allowed value: 7 */
            cwnd_tso_budget:1,    /* allowed values: {0, 1} */
            unused3:6,
            drain_to_target:1,    /* boolean */
            precise_ece_ack:1,    /* boolean */
            extra_acked_in_startup:1, /* allowed values: {0, 1} */
            fast_path:1;        /* boolean */
        u32 full_bw_thresh:10,    /* max allowed value: 1023 */
            startup_cwnd_gain:11,    /* max allowed value: 2047 */
            bw_probe_pif_gain:9,    /* max allowed value: 511 */
            usage_based_cwnd:1,     /* boolean */
            unused2:1;
        u16 probe_rtt_win_ms:14,    /* max allowed value: 16383 */
            refill_add_inc:2;    /* max allowed value: 3 */
        u16 extra_acked_gain:11,    /* max allowed value: 2047 */
            extra_acked_win_rtts:5; /* max allowed value: 31*/
        u16 pacing_gain[CYCLE_LEN]; /* max allowed value: 1023 */
        /* Mostly BBR v2 parameters below here: */
        u32 ecn_alpha_gain:8,    /* max allowed value: 255 */
            ecn_factor:8,        /* max allowed value: 255 */
            ecn_thresh:8,        /* max allowed value: 255 */
            beta:8;            /* max allowed value: 255 */
        u32 ecn_max_rtt_us:19,    /* max allowed value: 524287 */
            bw_probe_reno_gain:9,    /* max allowed value: 511 */
            full_loss_cnt:4;    /* max allowed value: 15 */
        u32 probe_rtt_cwnd_gain:8,    /* max allowed value: 255 */
            inflight_headroom:8,    /* max allowed value: 255 */
            loss_thresh:8,        /* max allowed value: 255 */
            bw_probe_max_rounds:8;    /* max allowed value: 255 */
        u32 bw_probe_rand_rounds:4, /* max allowed value: 15 */
            bw_probe_base_us:26,    /* usecs: 0..2^26-1 (67 secs) */
            full_ecn_cnt:2;        /* max allowed value: 3 */
        u32 bw_probe_rand_us:26,    /* usecs: 0..2^26-1 (67 secs) */
            undo:1,            /* boolean */
            tso_rtt_shift:4,    /* max allowed value: 15 */
            unused5:1;
        u32 ecn_reprobe_gain:9,    /* max allowed value: 511 */
            unused1:14,
            ecn_alpha_init:9;    /* max allowed value: 256 */
    } params;

    struct {
        u32 snd_isn; /* Initial sequence number */
        u32 rs_bw;      /* last valid rate sample bw */
        u32 target_cwnd; /* target cwnd, based on BDP */
        u8  undo:1,  /* Undo even happened but not yet logged */
            unused:7;
        char event;     /* single-letter event debug codes */
        u16 unused2;
    } debug;
};

struct bbr_context {
    u32 sample_bw;
    u32 target_cwnd;
    u32 log:1;
};


/*static u64 bbr_rate_bps(struct sock *sk, u64 rate)
{
    rate *= tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache);
    rate *= USEC_PER_SEC;
    rate = (rate >> BW_SCALE) << 3;
    return rate;
}*/

static void bbr_read(const struct sock *sk, void *cong_data)
{
    memcpy(cong_data, inet_csk_ca(sk),
            min_t(size_t, sizeof(struct bbr), ICSK_CA_PRIV_SIZE));
}

static inline int bbr_sprint(char *tbuf,  int n, const void *cong_data) {
    int copied = 0;
    // struct bbr *ca = (struct bbr *) cong_data;
    // copied += scnprintf(tbuf+copied, n-copied, " %llx %x", ca->maxbw_Bps, ca->pacing_gain);
    // copied += scnprintf(tbuf+copied, n-copied, " %x", ca->min_rtt_us);
    // copied += scnprintf(tbuf+copied, n-copied, " %x %x", ca->round_start, ca->rtt_cnt);
    // copied += scnprintf(tbuf+copied, n-copied, " %x %x", ca->mode, ca->cycle_idx);
    // copied += scnprintf(tbuf+copied, n-copied, " %x %x", ca->lt_is_sampling, ca->lt_rtt_cnt);
    // copied += scnprintf(tbuf+copied, n-copied, " %x %x", ca->lt_use_bw, ca->lt_bw_Bps);
    return copied;
}

struct congestion_ops bbr2_cong_ops __read_mostly = {
    .read = bbr_read,
    .sprint = bbr_sprint,
};
