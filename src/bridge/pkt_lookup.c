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

/*
 * Attempt to decap.
 *
 * Returns 0 if decap ok, -1 if decap failed.
 */
int
pkt_fwd_decap(struct thr_ctx *th, struct pkt *p)
{
	const char *buf;
	int len;
	const char *payload_buf;
	int payload_len;
	uint16_t hdrtype;
	const struct ip *iphdr;
	int pktlen;

	buf = p->buf;
	len = p->len;

	/* Short packet - just forward */
	if (len < 14)
		return (-1);

	payload_len = len;
	payload_buf = buf;

	/*
	 * Get the ethernet header type / packet length.
	 *
	 * This is pretty terrible - I only handle a subset of ethernet encaped
	 * frames here.
	 */
	/* XXX unaligned access */
	hdrtype = ((uint16_t *)payload_buf)[6];

	/* Advance payload buffer to after the ethertype/size field */
	payload_buf += 14;
	payload_len -= 14;

	/* If ETHERTYPE_VLAN, bump buf/len along a bit, re-decap */
	if (hdrtype == htons(ETHERTYPE_VLAN)) {
		/* Check we at least have that many bytes */
		if (payload_len < 2)
			return (-1);

		/* Skip VLAN header, etc */
		payload_buf += 2;
		payload_len -= 2;

		/* Re-update hdrtype */
		hdrtype = ((uint16_t *) payload_buf)[0];
	}

	/*
	 * Check if ethertype is IP. If it is, then we check;
	 * otherwise just forward it along.
	 */
	if (hdrtype != htons(ETHERTYPE_IP)) {
		/* Don't know; pass it on */
		return (-1);
	}

	/*
	 * Ok, it's IPv4; cool.
	 */
	iphdr = (const struct ip *) ((const char *) payload_buf);
	p->iphdr = iphdr;
	pktlen = payload_len;

	/* Short ipv4 frame */
	if (pktlen < sizeof(struct ip))
		return (-1);

	return (0);
}

/*
 * Check if a packet is to be forwareded.
 *
 * Return 0 if ok, < 0 if to not forward.
 */
int
pkt_fwd_check(struct thr_ctx *th, struct pkt *p)
{
	const struct ip *iphdr;
	struct in_addr src, dst;
	uint32_t score;

	/* Forward if it's not IPv4 */
	iphdr = p->iphdr;
	if (iphdr == NULL)
		return (0);

	/* Extract src/dst IPs */
	src = iphdr->ip_src;
	dst = iphdr->ip_dst;

	/* Do src/dst lookup */
	/*
	 * This is where we'd do a src/dst lookup in the (maybe prefetched)
	 * hash table.
	 */

	/* All ok - continue */
	return (0);
}
