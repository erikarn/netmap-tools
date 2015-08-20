#ifndef	__STATE_H__
#define	__STATE_H__

/*
 * Global context
 */
struct app_ctx {
	pthread_rwlock_t hash_rwlock;
};

/*
 * Per-thread context
 */
struct thr_ctx {
	struct app_ctx *app;
	pthread_t thr;
	int cpuid;
	struct nm_desc *pa, *pb;
	char *ifa, *ifb;
	int zerocopy;
	int burst;
	uint64_t lookup_hit, lookup_miss;
};

#endif
