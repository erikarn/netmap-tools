/*
 * (C) 2011-2014 Luigi Rizzo, Matteo Landi
 *
 * BSD license
 *
 * A netmap client to bridge two network interfaces
 * (or one interface and the host stack).
 *
 * $FreeBSD: stable/10/tools/tools/netmap/bridge.c 262151 2014-02-18 05:01:04Z luigi $
 */

#include <stdio.h>
#include <err.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/ethernet.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <pthread.h>
#include <pthread_np.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "state.h"
#include "pkt.h"
#include "pkt_lookup.h"

#define	MAXPKT	32

int verbose = 0;

static int do_abort = 0;
static int start_cpu = -1;
static int do_prefetch_ether = 1;
static int do_prefetch_hash = 1;
static int batch_size = 4;

static void
sigint_h(int sig)
{
	(void)sig;	/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}

static int
app_ctx_init(struct app_ctx *app)
{

	return (0);
}

static int
thr_ctx_setup(struct thr_ctx *th, char *ifa, char *ifb,
    int zerocopy, int burst, struct thr_ctx *parent, int cpuid)
{
	int nm_flags = 0;
	struct nm_desc *p_pa = NULL;

	bzero(th, sizeof(struct thr_ctx));

	th->ifa = strdup(ifa);
	th->ifb = strdup(ifb);
	th->zerocopy = zerocopy;
	th->burst = burst;
	th->cpuid = cpuid;

	/* Setup netmap rings */
	if (parent) {
		nm_flags |= NM_OPEN_NO_MMAP;
		p_pa = parent->pa;
	}
	th->pa = nm_open(ifa, NULL, nm_flags, p_pa);
	if (th->pa == NULL) {
		D("cannot open %s", ifa);
		exit(1);
	}

	th->pb = nm_open(ifb, NULL, NM_OPEN_NO_MMAP, th->pa);
	if (th->pb == NULL) {
		D("cannot open %s", ifb);
		nm_close(th->pa);
		exit(1);
	}
	th->zerocopy = th->zerocopy && (th->pa->mem == th->pb->mem);

	/* Done */
	return (0);
}

static int
thr_teardown(struct thr_ctx *ctx)
{

	if (ctx->pa)
		nm_close(ctx->pa);
	if (ctx->pb)
		nm_close(ctx->pb);

	free(ctx->ifa);
	free(ctx->ifb);

	return (0);
}

/*
 * how many packets on this set of queues ?
 *
 * Receive: how many frames in the receive path.
 * Transmit: how many slots are available to transmit.
 */
int
pkt_queued(struct nm_desc *d, int tx)
{
	u_int i, tot = 0;

	if (tx) {
		for (i = d->first_tx_ring; i <= d->last_tx_ring; i++) {
			tot += nm_ring_space(NETMAP_TXRING(d->nifp, i));
		}
	} else {
		for (i = d->first_rx_ring; i <= d->last_rx_ring; i++) {
			tot += nm_ring_space(NETMAP_RXRING(d->nifp, i));
		}
	}
	return tot;
}

/*
 * Populate the pkt batch from the netmap array.
 *
 * returns the number of entries; and sets nj to the next ring entry.
 */
static int
pkt_create_queue(struct netmap_ring *ring, struct pkt *pq, int limit, u_int *nj)
{
	int i, n;
	u_int j;

	j = *nj;

	/* Only do batches of MAXPKT */
	if (limit > MAXPKT)
		limit = MAXPKT;

	for (n = 0, i = 0; i < limit; i++) {
		struct netmap_slot *rs = &ring->slot[j];

		pq[i].buf = NETMAP_BUF(ring, rs->buf_idx);
		pq[i].len = rs->len;
		pq[i].iphdr = NULL;
		pq[i].slotid = j;

		j = nm_ring_next(ring, j);
		n++;
	}

	*nj = j;

	return (n);
}

static void
pkt_prefetch_etherhdr(struct pkt *pq, int n)
{
	int i, len;
	const char *buf;

	for (i = 0; i < n; i++) {
		buf = pq[i].buf;
		len = pq[i].len;
		if (len < 14)
			continue;

		/* Pre-fetch the ethertype */
		__builtin_prefetch(&buf[14]);
	}
}

static void
pkt_lookup_prefetch(struct thr_ctx *th, struct pkt *pq, int n, int do_prefetch)
{
	struct app_ctx *ctx = th->app;
	int i;

	for (i = 0; i < n; i++) {
		if (pq[i].iphdr == NULL)
			continue;

		/* XXX Here's where we'd do a hash bucket prefetch */
	}
}

static void
pkt_fwd_decap_batch(struct thr_ctx *th, struct pkt *pq, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		(void) pkt_fwd_decap(th, &pq[i]);
	}
}

static void
pkt_fwd_check_batch(struct thr_ctx *th, struct pkt *pq, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (pq[i].iphdr == NULL)
			pq[i].fwd = 1;
		else
			pq[i].fwd = ! (pkt_fwd_check(th, &pq[i]));
	}
}

static void
pkt_fwd_packets(struct thr_ctx *th, struct netmap_ring *rxring,
    struct netmap_ring *txring,
    struct pkt *pq, int n,
    u_int *txidx)
{
	struct netmap_slot *rs;
	struct netmap_slot *ts;
	int i;
	u_int t;

	t = *txidx;

	/* Flip or copy packets to tx, incr txidx as appropriate */
	for (i = 0; i < n; i++) {

		/* Don't forward if we're not supposed to */
		if (! pq[i].fwd)
			continue;

		rs = &rxring->slot[pq[i].slotid];
		ts = &txring->slot[t];

		ts->len = rs->len;
		if (th->zerocopy) {
			uint32_t pkt = ts->buf_idx;
			ts->buf_idx = rs->buf_idx;
			rs->buf_idx = pkt;
			/* report the buffer change. */
			ts->flags |= NS_BUF_CHANGED;
			rs->flags |= NS_BUF_CHANGED;
		} else {
			char *rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
			char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
			nm_pkt_copy(rxbuf, txbuf, ts->len);
		}

		/* Increment the transmit ring */
		t = nm_ring_next(txring, t);
	}
	*txidx = t;
}

/*
 * move up to 'limit' pkts from rxring to txring swapping buffers.
 */
static int
process_rings(struct thr_ctx *th, struct netmap_ring *rxring,
	    struct netmap_ring *txring, u_int limit, const char *msg)
{
	u_int j, k, m = 0;
	struct pkt pkts[MAXPKT];

	/* print a warning if any of the ring flags is set (e.g. NM_REINIT) */
	if (rxring->flags || txring->flags)
		D("%s rxflags %x txflags %x",
			msg, rxring->flags, txring->flags);
	j = rxring->cur; /* RX */
	k = txring->cur; /* TX */
	m = nm_ring_space(rxring);
	if (m < limit) {
		limit = m;
	}
	m = nm_ring_space(txring);
	if (m < limit) {
		limit = m;
	}
	m = limit;

	if (verbose)
		D("%s: start; rx=%u, tx=%u, limit=%d", __func__, j, k, limit);

	while (limit > 0) {
		const struct netmap_slot *rs = &rxring->slot[j];
		const struct netmap_slot *ts = &txring->slot[k];
		int n, i;
		int batch_limit;

		batch_limit = limit;
		if (batch_limit > batch_size)
			batch_limit = batch_size;

		/* Check for valid indexes */
		if (ts->buf_idx < 2 || rs->buf_idx < 2) {
			D("wrong index rx[%d] = %d  -> tx[%d] = %d",
				j, rs->buf_idx, k, ts->buf_idx);
			sleep(2);
		}

		/* Initialise the batched packet queue */
		n = pkt_create_queue(rxring, pkts, batch_limit, &j);
		if (verbose)
			D("%s: created; n=%d, j=%d", __func__, n, j);
		/*
		 * n is how many packets are in this list to iterate
		 * over; j is the end of the RX batch.
		 */

		/* Do prefetch on the set */
		if (do_prefetch_ether)
			pkt_prefetch_etherhdr(pkts, n);

		/* Do pkt decap */
		pkt_fwd_decap_batch(th, pkts, n);

		/* Do lookup prefetching and hash value calculation */
		pkt_lookup_prefetch(th, pkts, n, do_prefetch_hash);

		/* Do pkt_fwd_check on the set */
		pkt_fwd_check_batch(th, pkts, n);

		/*
		 * Walk the pkts list; any packet marked 'fwd' do so;
		 * else skip over it
		 */
		pkt_fwd_packets(th, rxring, txring, pkts, n, &k);

		/*
		 * Done; update limit as appropriate.
		 */
		limit -= n;
	}

	/*
	 * Update netmap state for the next poll() trip.
	 */
	rxring->head = rxring->cur = j;
	txring->head = txring->cur = k;
	if (verbose && m > 0)
		D("%s sent %d packets to %p", msg, m, txring);

	return (m);
}

/* move packts from src to destination */
static int
move(struct thr_ctx *th, struct nm_desc *src, struct nm_desc *dst, u_int limit)
{
	struct netmap_ring *txring, *rxring;
	u_int m = 0, si = src->first_rx_ring, di = dst->first_tx_ring;
	const char *msg = (src->req.nr_ringid & NETMAP_SW_RING) ?
		"host->net" : "net->host";

	while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
		rxring = NETMAP_RXRING(src->nifp, si);
		txring = NETMAP_TXRING(dst->nifp, di);
		ND("txring %p rxring %p", txring, rxring);
		if (nm_ring_empty(rxring)) {
			si++;
			continue;
		}
		if (nm_ring_empty(txring)) {
			di++;
			continue;
		}
		m += process_rings(th, rxring, txring, limit, msg);
	}

	return (m);
}


static void
usage(void)
{
	fprintf(stderr,
	    "usage: bridge [-v] [-i if] [-B batchsize] [-b burst] [-w wait_time]\n"
	    "              [-r numrings] [-C start cpuid]\n"
	    "              [-p <0|1>] [-P <0|1>] [iface]\n"
	    "              [-i if] contains one or more of 'ifa,ifb'\n");
	fprintf(stderr,
	    "    -p <0|1> - disable|enable ethertype prefetching\n");
	exit(1);
}

static int
thr_run_loop(struct thr_ctx *th)
{
	struct pollfd pollfd[2];

	/* setup poll(2) variables. */
	memset(pollfd, 0, sizeof(pollfd));
	pollfd[0].fd = th->pa->fd;
	pollfd[1].fd = th->pb->fd;

	D("Ready to go, %s 0x%x/%d <-> %s 0x%x/%d.",
		th->pa->req.nr_name, th->pa->first_rx_ring, th->pa->req.nr_rx_rings,
		th->pb->req.nr_name, th->pb->first_rx_ring, th->pb->req.nr_rx_rings);

	while (!do_abort) {
		int n0, n1, ret;
		pollfd[0].events = pollfd[1].events = 0;
		pollfd[0].revents = pollfd[1].revents = 0;

		/* Always poll for read readiness */
		pollfd[0].events = POLLIN;
		pollfd[1].events = POLLIN;

		/*
		 * If there's no space in the destination
		 * ring, select for POLLOUT.
		 *
		 * Otherwise, an ioctl() will be done to do a
		 * hard txsync, so as to make space for subsequent
		 * read packets.
		 */
		if (pkt_queued(th->pa, 1) == 0)
			pollfd[0].events |= POLLOUT;
		if (pkt_queued(th->pb, 1) == 0)
			pollfd[1].events |= POLLOUT;

		/*
		 * This at least triggers the read check, and
		 * will also schedule TX frames out if needed.
		 */
		ret = poll(pollfd, 2, 2500);

		if (ret <= 0 || verbose) {
		    D("poll %s [0] ev %x %x rx %d@%d tx %d,"
			     " [1] ev %x %x rx %d@%d tx %d",
				ret <= 0 ? "timeout" : "ok",
				pollfd[0].events,
				pollfd[0].revents,
				pkt_queued(th->pa, 0),
				NETMAP_RXRING(th->pa->nifp, th->pa->cur_rx_ring)->cur,
				pkt_queued(th->pa, 1),
				pollfd[1].events,
				pollfd[1].revents,
				pkt_queued(th->pb, 0),
				NETMAP_RXRING(th->pb->nifp, th->pb->cur_rx_ring)->cur,
				pkt_queued(th->pb, 1)
			);
		}
		if (ret < 0)
			continue;
		if (pollfd[0].revents & POLLERR) {
			struct netmap_ring *rx = NETMAP_RXRING(th->pa->nifp,
			    th->pa->cur_rx_ring);
			D("error on fd0, rx [%d,%d,%d)",
				rx->head, rx->cur, rx->tail);
		}
		if (pollfd[1].revents & POLLERR) {
			struct netmap_ring *rx = NETMAP_RXRING(th->pb->nifp,
			    th->pb->cur_rx_ring);
			D("error on fd1, rx [%d,%d,%d)",
				rx->head, rx->cur, rx->tail);
		}

		/*
		 * Next: the poll transmit side descriptors are only
		 * reclaimed when it's /just about/ to run out of
		 * descriptors (ie, it's done lazily.)
		 *
		 * So if we're about to run out transmit descriptor slots,
		 * don't wait until we fill the transmit side to have
		 * things reaped; just do a TXSYNC now.
		 *
		 * The poll() has already updated the driver side idea
		 * of transmit/receive availability, so check to see
		 * whether we have space.
		 */
		/*
		 * Check to see if there's enough transmit slots in th->pb
		 */
		if (pkt_queued(th->pa, 0) > pkt_queued(th->pb, 1)) {
			/* XXX spinloop? */
			while (ioctl(th->pb->fd, NIOCTXSYNC, NULL) != 0)
				usleep(1);
		}

		/*
		 * Check to see if there's enough transmit slots in th->pa
		 */
		if (pkt_queued(th->pb, 0) > pkt_queued(th->pa, 1)) {
			/* XXX spinloop? */
			while (ioctl(th->pa->fd, NIOCTXSYNC, NULL) != 0)
				usleep(1);
		}

		/* If we're read-ready, /then/ move */
		if (pollfd[1].revents & POLLIN) {
			move(th, th->pb, th->pa, th->burst);
		}
		if (pollfd[0].revents & POLLIN) {
			move(th, th->pa, th->pb, th->burst);
		}

		/*
		 * There's no need to call the ioctl() to flush;
		 * the next trip through poll() with POLLIN set
		 * will update the transmit pointer for us.
		 */
	}

	return (0);
}

static void *
thr_run(void *arg)
{
	struct thr_ctx *th = arg;

	if (th->cpuid != -1) {
		cpuset_t cpuset;

		CPU_ZERO(&cpuset);
		CPU_SET(th->cpuid % CPU_SETSIZE, &cpuset);
		pthread_setaffinity_np(pthread_self(), sizeof(cpuset_t),
		    &cpuset);
	}

	thr_run_loop(th);
	return (NULL);
}

/*
 * bridge [-v] if1 [if2]
 *
 * If only one name, or the two interfaces are the same,
 * bridges userland and the adapter. Otherwise bridge
 k* two intefaces.
 */
#define	MAX_IFLIST	128

int
main(int argc, char **argv)
{
	int ch;
	u_int burst = 1024, wait_link = 4;
	char *ifa = NULL, *ifb = NULL;
	char ifabuf[64] = { 0 };
	int zerocopy = 1;
	int nifs = 0;
	struct thr_ctx *th;
	int i;
	struct app_ctx app;
	char *iflist[128];

	fprintf(stderr, "%s built %s %s\n",
		argv[0], __DATE__, __TIME__);

	while ( (ch = getopt(argc, argv, "B:b:C:ci:f:p:P:r:vw:")) != -1) {
		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;
		case 'B':
			batch_size = atoi(optarg);
			if (batch_size > MAXPKT)
				batch_size = MAXPKT;
			break;
		case 'b':	/* burst */
			burst = atoi(optarg);
			break;
		case 'C':
			start_cpu = atoi(optarg);
			break;
		case 'i':	/* interface */
			if (nifs >= MAX_IFLIST) {
				printf("maximum iflist exceeded, is %d\n",
				    MAX_IFLIST);
				exit(1);
			}
			iflist[nifs] = strdup(optarg);
			nifs++;
			break;
		case 'c':
			zerocopy = 0; /* do not zerocopy */
			break;
		case 'p':
			do_prefetch_ether = atoi(optarg);
			break;
		case 'P':
			do_prefetch_hash = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			wait_link = atoi(optarg);
			break;
		}

	}

	argc -= optind;
	argv += optind;

	if (burst < 1 || burst > 8192) {
		D("invalid burst %d, set to 1024", burst);
		burst = 1024;
	}
	if (wait_link > 100) {
		D("invalid wait_link %d, set to 4", wait_link);
		wait_link = 4;
	}

	/* Setup app context */
	app_ctx_init(&app);

	/* Setup thread context */
	th = calloc(nifs, sizeof(struct thr_ctx));
	if (th == NULL) {
		err(1, "calloc: thr_ctx");
	}

	D("------- zerocopy %ssupported", zerocopy ? "" : "NOT ");

	for (i = 0; i < nifs; i++) {
		int cpuid;
		int ringid;
		char *ia, *ib;
		char *f;

		/* Split the interface into comma separated entries */
		f = strdup(iflist[i]);
		/* XXX error check */
		ia = strsep(&f, ",");
		ib = strsep(&f, ",");
		if (ia == NULL || ib == NULL) {
			printf("error: '%s': couldn't parse\n",
			    iflist[i]);
			exit(1);
		}
		if (strlen(ia) == 0 || strlen(ib) == 0) {
			printf("error: ifa=%s, ifb=%s, can't be blank\n",
			    ia, ib);
			exit(1);
		}

		if (start_cpu == -1)
			cpuid = -1;
		else
			cpuid = start_cpu + i;

		if (thr_ctx_setup(&th[i], ia, ib,
		    zerocopy, burst, (i == 0 ? NULL : &th[0]), cpuid) != 0)
			exit(127);
		th[i].app = &app;
		free(f);
	}

	/* .. and allocate netmap rings */

	D("burst: %d pkts; batch size %d packets; do_prefetch_ether=%d, do_prefetch_hash=%d",
	    burst,
	    batch_size,
	    do_prefetch_ether,
	    do_prefetch_hash);
	D("Wait %d secs for link to come up...", wait_link);
	sleep(wait_link);

	/* main loop */
	/* XXX should put this into main thread only? */
	signal(SIGINT, sigint_h);

	/* Start worker threads */
	for (i = 0; i < nifs; i++) {
		if (pthread_create(&th[i].thr, NULL, thr_run, &th[i]) != 0) {
			warn("pthread_create");
			goto finish;
		}
	}

	/* Join */
	for (i = 0; i < nifs; i++) {
		(void) pthread_join(th[i].thr, NULL);
	}
	D("exiting");

	/* Cleanup */
finish:
	for (i = 0; i < nifs; i++) {
		thr_teardown(&th[i]);
	}

	return (0);
}
