#ifndef	__PKT_LOOKUP_H__
#define	__PKT_LOOKUP_H__

extern	int pkt_fwd_decap(struct thr_ctx *th, struct pkt *p);
extern	int pkt_fwd_check(struct thr_ctx *th, struct pkt *p);

#endif
