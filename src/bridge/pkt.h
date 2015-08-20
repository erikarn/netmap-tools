#ifndef	__BRIDGE_PKT_H__
#define	__BRIDGE_PKT_H__

struct pkt {
	const char *buf;
	const struct ip *iphdr;
	int len;
	int slotid;
	int fwd;
};

#endif
