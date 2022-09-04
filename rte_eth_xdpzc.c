#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include <rte_cycles.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_bus_vdev.h>
#include <rte_string_fns.h>
#include <rte_common.h>
#include <rte_fbarray.h>

#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/bpf.h>

#include <immintrin.h>

#ifndef SOL_XDP
#define SOL_XDP 				283
#endif

#ifndef AF_XDP
#define AF_XDP 					44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif 

#define RTE_ETH_PCAP_SNAPSHOT_LEN 65535
#define RTE_ETH_PCAP_SNAPLEN 	ETHER_MAX_JUMBO_FRAME_LEN
#define RTE_ETH_PCAP_PROMISC    1
#define RTE_ETH_PCAP_TIMEOUT   -1

#define ETH_XDP_KIFACE_ARG     "kiface"
#define ETH_XDP_KIFACE_Q_ARG   "kqueue"
#define ETH_XDP_DATA_OFFSET    "data_offset"
#define ETH_XDP_XSKX_MAP       "xskxmap"

#define ETH_XDP_ARG_MAXLEN		64
#define RTE_PMD_XDP_MAX_QUEUES  1

#define ZERO256   _mm256_set1_epi32(0)  

#define MBUF_ZC			 		1 
#define SMP_MB_OPTIMIZED 		1
#define HW_OFFLOAD       		1
#define PMD_PERF   		 		0

#define NUM_FRAMES 				2048
#define XDP_FRAME_SIZE  		2048
#define XDP_FRM_HEAD_ROOM		0

#define FQ_NUM_DESCS			1024
#define CQ_NUM_DESCS            1024
#define TX_DESC_OFFSET          (FQ_NUM_DESCS * XDP_FRAME_SIZE)

#ifdef SIMD_OPTIMIZED
#define BATCH_SIZE				8
#else
#define BATCH_SIZE				64
#endif
#define TX_BATCH_SIZE			64

struct bpf_prog_load_attr {
	const uint8_t *file;
	enum bpf_prog_type prog_type;
	enum bpf_attach_type expected_attach_type;
	int ifindex;
};


struct xdp_umem_uqueue {
	uint32_t cached_prod;
	uint32_t cached_cons;
	uint32_t mask;
	uint32_t size;
	uint32_t *producer;
	uint32_t *consumer;
	uint64_t *ring;
	void *map;
};

struct xdp_umem {
	uint8_t *frames;
	struct xdp_umem_uqueue fq;
	struct xdp_umem_uqueue cq;
	int xsk_fd;
};

struct xdp_uqueue {
	uint32_t cached_prod;
	uint32_t cached_cons;
	uint32_t mask;
	uint32_t size;
	uint32_t *producer;
	uint32_t *consumer;
	struct xdp_desc *ring;
	struct pmd_internals *private_data;
	struct rte_mempool *mb_pool;
	uint16_t port_id;
	void *map;
};

struct pmd_process_private {
	int32_t   xsk_fd;
};

struct pmd_devargs {
	uint8_t   iface_name[ETH_XDP_ARG_MAXLEN]; 
	uint8_t   k_iface_name[ETH_XDP_ARG_MAXLEN]; 
	uint8_t   bpf_path[ETH_XDP_ARG_MAXLEN];
	uint32_t  data_offset;	
	uint32_t  kiface_q;
	int32_t   xsk_fd;
	uint8_t   xskx_map[ETH_XDP_ARG_MAXLEN];	
	int32_t   xskx_map_id;
};

struct pmd_internals {
	uint8_t   devargs[ETH_XDP_ARG_MAXLEN];
	struct xdp_uqueue rx; 
	struct xdp_uqueue tx;
	struct xdp_umem_reg mr; 
	struct xdp_umem  *umem;	
	struct pmd_devargs priv_data; 
	struct ether_addr eth_addr;
};

static const uint8_t *valid_arguments[] = {
	ETH_XDP_KIFACE_ARG, 	
	ETH_XDP_KIFACE_Q_ARG,
	ETH_XDP_DATA_OFFSET,
	ETH_XDP_XSKX_MAP,
	NULL
};

static struct rte_eth_link pmd_link = {
		.link_speed = ETH_SPEED_NUM_10G,
		.link_duplex = ETH_LINK_FULL_DUPLEX,
		.link_status = ETH_LINK_DOWN,
		.link_autoneg = ETH_LINK_FIXED,
};

static int32_t eth_xdpzc_logtype;
#define PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, eth_xdpzc_logtype, \
		"%s(): " fmt "\n", __func__, ##args)


static int
eth_dev_start(struct rte_eth_dev *dev)
{
	uint32_t i, key = 0, rx_queue = 0x0; /* TBD: take this as pmd argument */
	struct pmd_internals *internals = dev->data->dev_private;
	struct pmd_process_private *pp = dev->process_private;
	struct pmd_devargs *priv_data = &(internals->priv_data);
	struct bpf_map *map; 
	struct bpf_object *obj; 
	int prog_fd, qidconf_map = 0, xskx_map = 0;
	struct sockaddr_xdp sxdp;

	sxdp.sxdp_family = PF_XDP;
	sxdp.sxdp_queue_id = rx_queue;
	sxdp.sxdp_flags = XDP_ZEROCOPY;
	//sxdp.sxdp_flags = XDP_FLAGS_DRV_MODE;
	sxdp.sxdp_ifindex = if_nametoindex(priv_data->k_iface_name);
	if (!sxdp.sxdp_ifindex) { 
		PMD_LOG(ERR, "if_nametoindex() failed for interface: %s.\n", priv_data->k_iface_name);
		return -1;
	}

	PMD_LOG(INFO, "starting interface %s for XDP PMD.\n", priv_data->k_iface_name);
	
	if (priv_data->xskx_map_id <= 0) { 
		PMD_LOG(ERR, "bpf_map_get_fd_by_id() failed for %s map; Error: %s.\n",
				 priv_data->xskx_map, strerror(errno));
		return -1;
	}

	xskx_map = bpf_map_get_fd_by_id(priv_data->xskx_map_id);
	if (xskx_map < 0) { 
		PMD_LOG(ERR, "bpf_object__find_map_by_name() failed for xskx_map; Error: %s.\n", 
				strerror(errno));
		return -1;
	}

	if (bpf_map_update_elem(xskx_map, &key, &priv_data->xsk_fd, 0) != 0) {
		PMD_LOG(ERR, "bpf_map_update_elem() failed for xskx_map; Error: %s.\n", strerror(errno));
		return -1;
	}

	if (bind(priv_data->xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) != 0)	{ 
		PMD_LOG(ERR, "bind() failed for sxdp Error: %s.\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	dev->data->dev_link.link_status = ETH_LINK_UP;

	return 0;
}

/*
 * This function gets called when the current port gets stopped.
 * Is the only place for us to close all the tx streams dumpers.
 * If not called the dumpers will be flushed within each tx burst.
 */
static void
eth_dev_stop(struct rte_eth_dev *dev)
{
	uint32_t i, key = 0, rx_queue = 0x0; /* TBD: need to take this as pmd argument */
	struct pmd_internals *internals = dev->data->dev_private;
	struct pmd_devargs *priv_data = &(internals->priv_data);
	struct pmd_process_private *pp = dev->process_private;
	struct bpf_map *map; 
	struct bpf_object *obj; 
	int prog_fd, qidconf_map, xskx_map;
	
	PMD_LOG(INFO, "stopping interface %s for XDP PMD.\n", priv_data->k_iface_name);

	xskx_map = bpf_map_get_fd_by_id(priv_data->xskx_map_id);
	if (xskx_map < 0) { 
		PMD_LOG(ERR, "bpf_object__find_map_by_name() failed for xskx_map; Error: %s.\n", 
				strerror(errno));
		return -1;
	}

	if (bpf_map_delete_elem(xskx_map, &key) != 0) { 
		PMD_LOG(ERR, "bpf_map_delete_elem() failed for qidconf_map; Error: %s.\n",
				strerror(errno));
		return -1;
	}	

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;

	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;

	dev->data->dev_link.link_status = ETH_LINK_DOWN;
}

static inline uint32_t umem_nb_free(struct xdp_umem_uqueue *q, uint32_t nb)
{
	uint32_t free_entries = q->cached_cons - q->cached_prod;

	if (free_entries >= nb)
		return free_entries;

	/* Refresh the local tail pointer */
	q->cached_cons = *q->consumer + q->size;

	return q->cached_cons - q->cached_prod;
}

static inline uint32_t xq_nb_free(struct xdp_uqueue *q, uint32_t ndescs)
{
	uint32_t free_entries = q->cached_cons - q->cached_prod;

	if (free_entries >= ndescs)
		return ndescs;

	/* Refresh the local tail pointer */
	q->cached_cons = *q->consumer + q->size;

	return q->cached_cons - q->cached_prod;
}

static inline uint32_t umem_nb_avail(struct xdp_umem_uqueue *q, uint32_t nb)
{
	uint32_t entries = q->cached_prod - q->cached_cons;

	if (entries == 0) {
		q->cached_prod = *q->producer;
		entries = q->cached_prod - q->cached_cons;
	}

	return (entries > nb) ? nb : entries;
}

static inline uint32_t xq_nb_avail(struct xdp_uqueue *q, uint32_t ndescs)
{
	uint32_t entries = q->cached_prod - q->cached_cons;

	if (entries == 0) {
		q->cached_prod = *q->producer;
		entries = q->cached_prod - q->cached_cons;
	}

	return (entries > ndescs) ? ndescs : entries;
}

static inline int32_t umem_fill_to_kernel2(struct xdp_umem_uqueue *fq, 
							  struct xdp_desc *d,
		                      size_t nb)
{
	uint32_t i;

	if (umem_nb_free(fq, nb) < nb)
		return -ENOSPC;

	for (i = 0; i < nb; i++) {
		uint32_t idx = fq->cached_prod++ & fq->mask;
		d[i].len = 0; /* TBD */ 
		fq->ring[idx] = d[i].addr;
	}

#if !SMP_MB_OPTIMIZED
	rte_smp_wmb();
#endif

	*fq->producer = fq->cached_prod;

	return 0;
}

static inline int32_t umem_fill_to_kernel(struct xdp_umem_uqueue *fq, uint64_t *d,
		                      size_t nb)
{
	uint32_t i;

	if (umem_nb_free(fq, nb) < nb)
		return -ENOSPC;

	for (i = 0; i < nb; i++) {
		uint32_t idx = fq->cached_prod++ & fq->mask;

		fq->ring[idx] = d[i];
	}

#if !SMP_MB_OPTIMIZED
	rte_smp_wmb();
#endif
	*fq->producer = fq->cached_prod;

	return 0;
}

static inline size_t umem_complete_from_kernel(struct xdp_umem_uqueue *cq,
		                           uint64_t *d, size_t nb)
{
	uint32_t idx, i, entries = umem_nb_avail(cq, nb);

#if !SMP_MB_OPTIMIZED
	rte_smp_rmb();
#endif
	for (i = 0; i < entries; i++) {
		idx = cq->cached_cons++ & cq->mask;
		d[i] = cq->ring[idx];
	}

	if (entries > 0) {
#if !SMP_MB_OPTIMIZED
		rte_smp_wmb();
#endif
		*cq->consumer = cq->cached_cons;
	}

	return entries;
}

static inline void *xq_get_data(struct xdp_umem *umem, uint64_t addr) 
{ 
	return &umem->frames[addr];
}
static inline int32_t xq_deq(struct xdp_uqueue *uq,
		             struct xdp_desc *descs,
			                  int32_t ndescs)
{
	struct xdp_desc *r = uq->ring;
	uint32_t idx;
	int32_t i, entries;

	entries = xq_nb_avail(uq, ndescs);

#if !SMP_MB_OPTIMIZED
	rte_smp_rmb();
#endif
	for (i = 0; i < entries; i++) {
		idx = uq->cached_cons++ & uq->mask;
		descs[i] = r[idx];
	}

	if (entries > 0) {
#if !SMP_MB_OPTIMIZED
		rte_smp_wmb();
#endif
		*uq->consumer = uq->cached_cons;
	}

	return entries;
}

static inline int32_t  xq_enq(struct xdp_uqueue *uq,  
							const struct xdp_desc *descs, 
							uint32_t ndescs) 
{ 
    struct xdp_desc *r = uq->ring;
    unsigned int i;

    /*  Redundant check -- avoiding
     *  if (xq_nb_free(uq, ndescs) < ndescs)
     *   return -ENOSPC;
     */   
    for (i = 0; i < ndescs; i++) {
        uint32_t idx = uq->cached_prod++ & uq->mask;

        r[idx].addr = descs[i].addr;
        r[idx].len  = descs[i].len;
    }

#if !SMP_MB_OPTIMIZED
    rte_smp_wmb();
#endif
    *uq->producer = uq->cached_prod;

    return 0;
}

#define XDP_BUF_TO_ADDR(b, u) ((uint64_t)b - (uint64_t)u->frames) 

void 
xdp_buf_release_to_fq(void *addr, void *opaque) 
{
	struct xdp_umem *umem = (struct xdp_umem *)opaque;
	uint64_t desc_addr = XDP_BUF_TO_ADDR(addr, umem);
	
	umem_fill_to_kernel(&umem->fq, &desc_addr, 0x1);
}

static uint16_t
eth_xdp_full_zc_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts) 
{ 
	struct xdp_desc descs[BATCH_SIZE]; 
	struct xdp_uqueue *rxq = (struct xdp_uqueue *)queue; 
	struct xdp_umem *umem = rxq->private_data->umem; 
	uint16_t rcvd, i, buf_size, pkt_offset = rxq->private_data->priv_data.data_offset;

	rcvd = xq_deq(rxq, descs, (nb_pkts>BATCH_SIZE)?BATCH_SIZE:nb_pkts);
	if (unlikely(!rcvd)) { 
		PMD_LOG(DEBUG, " requested for nb_pkts (%u) no packets from device!\n", nb_pkts);
		return 0;
	}

	if (rte_pktmbuf_alloc_bulk(rxq->mb_pool, bufs, rcvd)) { 	
		PMD_LOG(ERR, "Dropping XDP-ZC packet no buffer availability %d packets burst", rcvd);
		/* TBD: Increment drop counters */

		PMD_LOG(DEBUG, "rte_mempool_avail_count %u rte_mempool_in_use_count %u",
			rte_mempool_avail_count(rxq->mb_pool),
			rte_mempool_in_use_count(rxq->mb_pool) );
		/* TBD: release the XDP descs to FQ */	
		return 0;   
	} 
	nb_pkts	= 0;

	uint8_t *buf_addr;
	uint16_t buf_len = XDP_FRAME_SIZE;
	rte_iova_t buf_iova;	
	struct rte_mbuf_ext_shared_info *shinfo; 

	i = 0;
	{
 		buf_addr = xq_get_data(umem, descs[i].addr); 
		shinfo = rte_pktmbuf_ext_shinfo_init_helper(buf_addr, &buf_len, xdp_buf_release_to_fq, umem); 
		if (unlikely(!shinfo)) goto RX_ERR;

		buf_iova = 0; /*TBD: va2pa(buf_addr)*/ 	
		rte_pktmbuf_attach_extbuf(bufs[i], buf_addr, buf_iova, buf_len, shinfo);
		rte_prefetch0(bufs[i]);
	}

	for (; i < (rcvd - 1); i++) {
		bufs[i]->data_len = (uint16_t)descs[i].len;
#ifdef HW_OFFLOAD
		bufs[i]->data_off  = pkt_offset;  /* skip private data */
		bufs[i]->data_len -= pkt_offset; 
#endif 
		bufs[i]->pkt_len   = bufs[i]->data_len;
		bufs[i]->port 	   = rxq->port_id;

 		buf_addr = xq_get_data(umem, descs[i + 1].addr); 
		shinfo = rte_pktmbuf_ext_shinfo_init_helper(buf_addr, &buf_len, xdp_buf_release_to_fq, umem); 
		if (unlikely(!shinfo)) goto RX_ERR;

		buf_iova = 0; /*TBD: va2pa(buf_addr)*/ 	
		rte_pktmbuf_attach_extbuf(bufs[i + 1], buf_addr, buf_iova, buf_len, shinfo);
		rte_prefetch0(bufs[i + 1]);
	}

	{
		bufs[i]->data_len = (uint16_t)descs[i].len;
#ifdef HW_OFFLOAD
		bufs[i]->data_off  = pkt_offset;  /* skip private data */
		bufs[i]->data_len -= pkt_offset; 
#endif 
		bufs[i]->pkt_len   = bufs[i]->data_len;
		bufs[i]->port 	   = rxq->port_id;
	}
RX_ERR: //TBD

	return rcvd;
}

static uint16_t
eth_xdp_zc_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct xdp_desc descs[BATCH_SIZE]; 
	struct xdp_uqueue *rxq = (struct xdp_uqueue *)queue; 
	struct xdp_umem *umem = rxq->private_data->umem; 
	uint16_t rcvd, i, buf_size, pkt_offset = rxq->private_data->priv_data.data_offset;

	rcvd = xq_deq(rxq, descs, (nb_pkts>BATCH_SIZE)?BATCH_SIZE:nb_pkts);
	if (unlikely(!rcvd)) { 
		PMD_LOG(DEBUG, " requested for nb_pkts (%u) no packets from device!\n", nb_pkts);
		return 0;
	}

	if (rte_pktmbuf_alloc_bulk(rxq->mb_pool, bufs, rcvd)) { 	
		PMD_LOG(ERR, "Dropping XDP-ZC packet no buffer availability %d packets burst", rcvd);
		/* TBD: Increment drop counters */

		PMD_LOG(DEBUG, "rte_mempool_avail_count %u rte_mempool_in_use_count %u",
			rte_mempool_avail_count(rxq->mb_pool),
			rte_mempool_in_use_count(rxq->mb_pool) );
		return 0;   
	} 
	
#if !PMD_PERF
	nb_pkts = 0;

#ifdef SIMD_OPTIMIZED
	__m256i a = _mm256_setr_epi32 (
			descs[7].len,
			descs[6].len,
			descs[5].len,
			descs[4].len,
			descs[3].len,
			descs[2].len,
			descs[1].len,
			descs[0].len);
	__m256i desc_empty = _mm256_cmpeq_epi32 (a, ZERO256);
#endif	

	i = 0;
	uint8_t *pkt;

 	pkt = xq_get_data(umem, descs[i].addr); 
#ifndef HW_OFFLOAD
	void *pkt_buf = rte_pktmbuf_mtod(bufs[i], void *); 
#else
	void *pkt_buf = rte_mbuf_to_priv(bufs[i]); 
#endif
	buf_size = rte_pktmbuf_data_room_size(rxq->mb_pool) - RTE_PKTMBUF_HEADROOM;

	rte_prefetch0(pkt_buf);
	rte_prefetch0(pkt);

	for (; i < (rcvd - 1); ) {
		if (likely(descs[i].len <= buf_size)) {
			rte_memcpy(pkt_buf, pkt, descs[i].len); 
			bufs[i]->data_len = (uint16_t)descs[i].len;
#ifdef HW_OFFLOAD
			bufs[i]->data_len -= pkt_offset; 
			bufs[i]->data_off = (sizeof(struct rte_mbuf) + pkt_offset); /* packet data */
#endif
		} else {
			/* TBD: Try read jumbo frame into multi mbufs. */
		}

		bufs[i]->pkt_len = (uint16_t)descs[i].len;
#ifdef HW_OFFLOAD
		bufs[i]->pkt_len -= pkt_offset; 
#endif 
		bufs[i]->port 	 = rxq->port_id;
#if !SMP_MB_OPTIMIZED
		rte_smp_wmb();
#endif
		{
			i += 1;
 			pkt = xq_get_data(umem, descs[i].addr); 
			pkt_buf = rte_pktmbuf_mtod(bufs[i], void *); 

			rte_prefetch0(pkt_buf);
			rte_prefetch0(pkt);
		}
	}		

	{
		if (likely(descs[i].len <= buf_size)) {
			rte_memcpy(pkt_buf, pkt, descs[i].len); 
			bufs[i]->data_len = (uint16_t)descs[i].len;
#ifdef HW_OFFLOAD
			bufs[i]->data_len -= pkt_offset; 
			bufs[i]->data_off = (sizeof(struct rte_mbuf) + pkt_offset); /* packet data */
#endif
		} else {
			/* TBD: Try read jumbo frame into multi mbufs. */
		}

		bufs[i]->pkt_len = bufs[i]->data_len; /* multi segment case -- TBD */
		bufs[i]->port 	 = rxq->port_id;
#if !SMP_MB_OPTIMIZED
		rte_smp_wmb();
#endif
	}
	nb_pkts += (i + 1);
#endif
	umem_fill_to_kernel2(&umem->fq, descs, rcvd);

#if !PMD_PERF
	while (unlikely(nb_pkts < rcvd--)) {
		rte_prefetch0(bufs[rcvd]);
		rte_pktmbuf_free(bufs[rcvd]);
	}
#endif

	return nb_pkts;
}

/*
 * Callback to handle sending packets through a real NIC.
 */
static uint16_t
eth_xdp_full_zc_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct xdp_desc descs[TX_BATCH_SIZE]; 
	struct xdp_uqueue *txq = (struct xdp_uqueue *)queue; 
	struct xdp_umem *umem = txq->private_data->umem;
	uint16_t pkts_tx, i, actual_buff_count = nb_pkts;
	void *addrs[TX_BATCH_SIZE];

#if PMD_PERF
	for (i = 0; i < nb_pkts; i++)
		rte_pktmbuf_free(bufs[i]);

	return nb_pkts;
#else
	if (unlikely(!nb_pkts)) return 0;

	int min = RTE_MIN(xq_nb_free(txq, nb_pkts), TX_BATCH_SIZE);

	nb_pkts = (min > nb_pkts) ? nb_pkts : min;
	pkts_tx = umem_complete_from_kernel(&umem->cq, (uint64_t *)&addrs[0], nb_pkts);

	uint8_t *buf_addr;
	uint16_t buf_len = XDP_FRAME_SIZE;
	rte_iova_t buf_iova;	
	struct rte_mbuf_ext_shared_info *shinfo; 

	if (likely(pkts_tx)) {
		i = 0;
		void *umem_buf = &umem->frames[(uint64_t)addrs[i]];

		rte_prefetch0(bufs[i]);
		descs[i].len = bufs[i]->data_len;

		for (; i < (pkts_tx - 1); ) {
			if (likely(RTE_MBUF_HAS_EXTBUF(bufs[i]))) { 
				shinfo = rte_pktmbuf_ext_shinfo_init_helper(umem_buf, 
								&buf_len, xdp_buf_release_to_fq, umem); 
				if (unlikely(!shinfo)) goto TX_ERROR; //TBD: Error handling(fall-back)

				/* swap with pseudo xdp frame */
				umem_buf = rte_atomic64_exchange(&bufs[i]->buf_addr, umem_buf);	
				descs[i].addr = (uint64_t)XDP_BUF_TO_ADDR(umem_buf, umem);
			} else { 
				void *pkt_buf = rte_pktmbuf_mtod(bufs[i], void *);

				rte_prefetch0(pkt_buf);
				rte_prefetch0(umem_buf);

				descs[i].addr = (uint64_t)addrs[i];
				rte_memcpy(umem_buf, pkt_buf, bufs[i]->data_len);
			} 
			/* Prefetch the next packet */
			{	
				i++;
				umem_buf = &umem->frames[(uint64_t)addrs[i]];

				rte_prefetch0(bufs[i]);
				descs[i].len = bufs[i]->data_len;
			}	
		}

		if (likely(RTE_MBUF_HAS_EXTBUF(bufs[i]))) { 
			shinfo = rte_pktmbuf_ext_shinfo_init_helper(umem_buf, 
						&buf_len, xdp_buf_release_to_fq, umem); 
			if (unlikely(!shinfo)) goto TX_ERROR; //TBD: Error handling(fall-back)

			/* swap with pseudo xdp frame */
			umem_buf = rte_atomic64_exchange(&bufs[i]->buf_addr, umem_buf);	
			descs[i].addr = (uint64_t)XDP_BUF_TO_ADDR(umem_buf, umem);
		} else { 
			void *pkt_buf = rte_pktmbuf_mtod(bufs[i], void *);

			rte_prefetch0(pkt_buf);
			rte_prefetch0(umem_buf);

			descs[i].addr = (uint64_t)addrs[i];

			rte_memcpy(umem_buf, pkt_buf, bufs[i]->data_len);
		} 

		int32_t ret = xq_enq(txq, descs, pkts_tx);
		if (unlikely(ret)) {
			/* TBD */
			pkts_tx = 0;
			goto TX_ERROR;
		}

		ret = sendto(umem->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0); 
		if (unlikely(ret < 0)) { 
			/* TBD: Error counters */
			pkts_tx = 0;
		}
	} 
#endif //PMD_PERF
TX_ERROR:
	for (i = 0; i < actual_buff_count; i++) {
		rte_prefetch0(bufs[i]);
		rte_pktmbuf_free(bufs[i]);
	}

	return nb_pkts;
}

/*
 * Callback to handle sending packets through a real NIC.
 */
static uint16_t
eth_xdp_zc_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct xdp_desc descs[TX_BATCH_SIZE]; 
	struct xdp_uqueue *txq = (struct xdp_uqueue *)queue; 
	struct xdp_umem *umem = txq->private_data->umem;
	void *addrs[TX_BATCH_SIZE];
	uint16_t pkts_tx, i, actual_buff_count = nb_pkts;

#if PMD_PERF
	for (i = 0; i < nb_pkts; i++)
		rte_pktmbuf_free(bufs[i]);

	return nb_pkts;
#else
	if (unlikely(!nb_pkts)) return 0;

	int min = RTE_MIN(xq_nb_free(txq, nb_pkts), TX_BATCH_SIZE);

	nb_pkts = (min > nb_pkts) ? nb_pkts : min;

	pkts_tx = umem_complete_from_kernel(&umem->cq, (uint64_t *)&addrs[0], nb_pkts);

	if (likely(pkts_tx)) {
			i = 0;

			void *pkt_buf = rte_pktmbuf_mtod(bufs[i], void *); 
			void *umem_buf = &umem->frames[(uint64_t)addrs[i]];

			rte_prefetch0(pkt_buf);
			rte_prefetch0(umem_buf);

			for (; i < (pkts_tx -1); ) {
				descs[i].addr = (uint64_t)addrs[i]; 
				//descs[i].len = bufs[i]->pkt_len; /* TBD for multi-segments*/
				descs[i].len = bufs[i]->data_len;
				descs[i].options = 0;
				rte_memcpy(umem_buf, pkt_buf, bufs[i]->data_len);
				/* Prefetch the next packet */
			 	{
					
					i += 1;
					pkt_buf = rte_pktmbuf_mtod(bufs[i], void *); 
					umem_buf = &umem->frames[(uint64_t)addrs[i]];

					rte_prefetch0(pkt_buf); 
					rte_prefetch0(umem_buf);
				}
			}

			/* Copy the last packet */	
			{
				descs[i].addr = (uint64_t)addrs[i];
				descs[i].len = bufs[i]->data_len;
				descs[i].options = 0;

   		        rte_memcpy(umem_buf, pkt_buf, bufs[i]->data_len);
			}

			int32_t ret = xq_enq(txq, descs, pkts_tx);
			if (unlikely(ret)) {
				/* TBD */
				pkts_tx = 0;
				goto TX_ERROR;
			}

			ret = sendto(umem->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0); 
			if (unlikely(ret < 0)) { 
				/* TBD: Error counters */
				pkts_tx = 0;
			}
	} 
#endif //PMD_PERF

TX_ERROR:
	for (i = 0; i < actual_buff_count; i++) {
		rte_prefetch0(bufs[i]);
		rte_pktmbuf_free(bufs[i]);
	}

	return pkts_tx;
}

static int
eth_dev_configure(struct rte_eth_dev *dev)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct xdp_umem_reg *mr = &(internals->mr);
	struct pmd_devargs *priv_data = &(internals->priv_data);
	struct xdp_mmap_offsets off;
	socklen_t optlen; 
	int32_t  ret; 
	void *buf; 
	uint32_t fq_size = FQ_NUM_DESCS, cq_size = CQ_NUM_DESCS;

	mr->addr = (uint64_t)rte_malloc(NULL, NUM_FRAMES * XDP_FRAME_SIZE, getpagesize());
	if (!mr->addr) 
	{ 
		PMD_LOG(ERR, "rte_malloc() failed for size (%u).\n", NUM_FRAMES*XDP_FRAME_SIZE);
		return -1;
	}

    if (rte_is_aligned(mr->addr, (int)log2(getpagesize())) == 0) {
        PMD_LOG(ERR, "metadata offset should be (int)log2(%d), addr (%p)!\n", getpagesize(), mr->addr);
        return -2;
    }

	mr->len  = (uint64_t)(NUM_FRAMES * XDP_FRAME_SIZE);
	mr->chunk_size = XDP_FRAME_SIZE; 
	mr->headroom = XDP_FRM_HEAD_ROOM;

	ret=setsockopt(priv_data->xsk_fd, SOL_XDP, XDP_UMEM_REG, mr, sizeof(struct xdp_umem_reg));
	if (ret != 0)  { 
		PMD_LOG(ERR, "setsockopt() failed for XDP_UMEM_REG error: %s ret %d\n", strerror(errno), ret);
		rte_free( mr->addr);
		return -1;
	}

	if (setsockopt(priv_data->xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING, &fq_size, sizeof(int)) != 0)  { 
		PMD_LOG(ERR, "setsockopt() failed for XDP_UMEM_FILL_RING.\n");
		rte_free( mr->addr);
		return -1;
	}

	if (setsockopt(priv_data->xsk_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &cq_size, sizeof(int)) != 0)  { 
		PMD_LOG(ERR, "setsockopt() failed for XDP_UMEM_COMPLETION_RING.\n");
		rte_free(mr->addr);
		return -1;
	}
	
	optlen = sizeof(off);
	ret = getsockopt(priv_data->xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen);
	if (ret != 0) { 
		PMD_LOG(ERR, "getsockopt() failed for XDP_MMAP_OFFSETS.\n");
		rte_free(mr->addr);
		return -1;
	}

	internals->umem = rte_calloc(NULL, 1, sizeof(struct xdp_umem), 0);
	if (!internals->umem) 
	{ 
		rte_free(mr->addr);
		PMD_LOG(ERR, "rte_malloc() failed for xdp_umem Error: %s .\n",strerror(errno));
		return -1;
	}

	internals->umem->fq.map = mmap(NULL, off.fr.desc + 
			FQ_NUM_DESCS * sizeof(uint64_t), 
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, priv_data->xsk_fd,
			XDP_UMEM_PGOFF_FILL_RING);
	if (internals->umem->fq.map == MAP_FAILED)
	{ 
		rte_free(internals->umem);
		rte_free(mr->addr);
		PMD_LOG(ERR, "mmap failed for fq.map Error: %s .\n",strerror(errno));
		return -1;
	}

	internals->umem->fq.mask = FQ_NUM_DESCS - 1;
	internals->umem->fq.size = FQ_NUM_DESCS;
	internals->umem->fq.producer = internals->umem->fq.map + off.fr.producer;
	internals->umem->fq.consumer = internals->umem->fq.map + off.fr.consumer; 
	internals->umem->fq.ring = internals->umem->fq.map + off.fr.desc; 
	internals->umem->fq.cached_cons = FQ_NUM_DESCS; 

	internals->umem->cq.map = mmap(NULL, off.cr.desc + 
			CQ_NUM_DESCS * sizeof(uint64_t), 
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, priv_data->xsk_fd,
			XDP_UMEM_PGOFF_COMPLETION_RING);
	if (internals->umem->cq.map == MAP_FAILED)
	{ 
		rte_free(internals->umem);
		rte_free(mr->addr);
		PMD_LOG(ERR, "mmap failed for cq.map Error: %s .\n",strerror(errno));
		return -1;
	}
	internals->umem->cq.mask = CQ_NUM_DESCS - 1;
	internals->umem->cq.size = CQ_NUM_DESCS;
	internals->umem->cq.producer = internals->umem->cq.map + off.cr.producer;
	internals->umem->cq.consumer = internals->umem->cq.map + off.cr.consumer; 
	internals->umem->cq.ring = internals->umem->cq.map + off.cr.desc; 
	internals->umem->frames = mr->addr;
	internals->umem->xsk_fd = priv_data->xsk_fd;
	internals->umem->cq.cached_cons = 0; 
	internals->umem->cq.cached_prod = CQ_NUM_DESCS; 

	return 0;
}

static void
eth_dev_info(struct rte_eth_dev *dev,
		struct rte_eth_dev_info *dev_info)
{

	struct pmd_internals *internals = (struct pmd_internals *)
						dev->data->dev_private;

	dev_info->max_rx_queues = 0x1; 
	dev_info->max_tx_queues = 0x1; 
	dev_info->driver_name = dev->device->driver->name; 

	return 0;
}

static void
eth_dev_close(struct rte_eth_dev *eth_dev __rte_unused)
{
	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		PMD_LOG(ERR, "failure not supported in secondary!\n");
			return -EPERM;
	}

	struct pmd_internals *internals = (struct pmd_internals *)
					 	eth_dev->data->dev_private;
	int ret; 

	/* Close the XDP socket */
	ret = close(internals->priv_data.xsk_fd);
	if (ret != 0) 
		PMD_LOG(ERR, "Error closing xdp socket [%d]\n", ret);
}

static int
eth_link_update(struct rte_eth_dev *dev __rte_unused,
		int wait_to_complete __rte_unused)
{
	return 0;
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev,
		uint16_t queue_idx,
		uint16_t nb_rx_desc,
		uint32_t socket_id __rte_unused,
		const struct rte_eth_rxconf *rx_conf __rte_unused,
		struct rte_mempool *mb_pool)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct pmd_devargs *priv_data = &(internals->priv_data);
	struct xdp_mmap_offsets off;
	socklen_t optlen; 
	int32_t  ret, i; 

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		PMD_LOG(ERR, "failure not supported in secondary!\n");
			return -EPERM;
	}

	if (queue_idx >= 0x1) {  /* TBD: check for max.rxq instead of 1 */
		PMD_LOG(WARNING, " queue_idx > max.rxqs. Hence forcing to 0\n");
		queue_idx = 0; 
	}

	if (setsockopt(priv_data->xsk_fd, SOL_XDP, XDP_RX_RING, &nb_rx_desc, sizeof(int)) != 0)  { 
		PMD_LOG(ERR, "setsockopt() failed for XDP_UMEM_COMPLETION_RING.\n");
		rte_free(internals->mr.addr);
		return -1;
	}
	
	optlen = sizeof(off);
	ret = getsockopt(priv_data->xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen);
	if (ret != 0) { 
		PMD_LOG(ERR, "getsockopt() failed for XDP_MMAP_OFFSETS.\n");
		rte_free(internals->mr.addr);
		return -1;
	}

	internals->rx.map = mmap(NULL, off.rx.desc + 
			nb_rx_desc * sizeof(struct xdp_desc), 
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, priv_data->xsk_fd,
			XDP_PGOFF_RX_RING);
	if (internals->rx.map == MAP_FAILED)
	{ 
		PMD_LOG(ERR, "mmap() failed for RX MAP Error: %s.\n",strerror(errno));
		return -1;
	}
	
	for (i = 0; i < nb_rx_desc * XDP_FRAME_SIZE; i += XDP_FRAME_SIZE) { 
		if (umem_fill_to_kernel(&internals->umem->fq, &i, 1) != 0)	{
			PMD_LOG(ERR, "umem_fill_to_kernel fq failed at i: %d Error: %s .",i, strerror(errno));
			return -1;
		}
	}

	internals->rx.mask = nb_rx_desc - 1;
	internals->rx.size = nb_rx_desc;
	internals->rx.producer = internals->rx.map + off.rx.producer;
	internals->rx.consumer = internals->rx.map + off.rx.consumer; 
	internals->rx.ring = internals->rx.map + off.rx.desc; 
	internals->rx.cached_cons = (nb_rx_desc & internals->rx.mask); 
	internals->rx.mb_pool = mb_pool;
	internals->rx.port_id = dev->data->port_id;
#if 0
	internals->rx.queue_id = queue_idx; /* TBD: while adding multiq support */
#endif
	internals->rx.private_data = internals;

	dev->data->rx_queues[queue_idx] = &(internals->rx);

	return 0;
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev,
		uint16_t tx_queue_id,
		uint16_t nb_tx_desc,
		uint32_t socket_id __rte_unused,
		const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct pmd_internals *internals = dev->data->dev_private;
	struct pmd_devargs *priv_data = &(internals->priv_data);
	struct xdp_mmap_offsets off;
	socklen_t optlen; 
	int32_t  ret, i; 

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		PMD_LOG(ERR, "failure not supported in secondary!\n");
			return -EPERM;
	}

	if (setsockopt(priv_data->xsk_fd, SOL_XDP, XDP_TX_RING, &nb_tx_desc, sizeof(int)) != 0)  { 
		PMD_LOG(ERR, "setsockopt() failed for XDP_UMEM_COMPLETION_RING.\n");
		rte_free(internals->mr.addr);
		return -1;
	}
	
	optlen = sizeof(off);
	ret = getsockopt(priv_data->xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen);
	if (ret != 0) { 
		PMD_LOG(ERR, "getsockopt() failed for XDP_MMAP_OFFSETS.\n");
		rte_free(internals->mr.addr);
		return -1;
	}

	internals->tx.map = mmap(NULL, off.tx.desc + 
			nb_tx_desc * sizeof(struct xdp_desc), 
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, priv_data->xsk_fd,
			XDP_PGOFF_TX_RING);
	if (internals->tx.map == MAP_FAILED)
	{ 
		PMD_LOG(ERR, "mmap() failed for TX map Error: %s.\n",strerror(errno));
		return -1;
	}
	
	for (i = TX_DESC_OFFSET; i < (TX_DESC_OFFSET + (nb_tx_desc * XDP_FRAME_SIZE)); i += XDP_FRAME_SIZE) {
		if (umem_fill_to_kernel(&internals->umem->cq, &i, 1) != 0)	{
			PMD_LOG(ERR, "umem_fill_to_kernel cq failed at i: %d Error: %s.\n",i, strerror(errno));
			return -1;
		}
	}

	internals->tx.mask =  nb_tx_desc - 1;
	internals->tx.size = nb_tx_desc;
	internals->tx.producer = internals->tx.map + off.tx.producer;
	internals->tx.consumer = internals->tx.map + off.tx.consumer; 
	internals->tx.ring = internals->tx.map + off.tx.desc; 
	//internals->tx.cached_cons = (nb_tx_desc & internals->tx.mask); 
	//internals->tx.cached_prod = (nb_tx_desc & internals->tx.mask); 
	internals->tx.port_id = dev->data->port_id;

	internals->tx.private_data = internals;

	dev->data->tx_queues[0] = &(internals->tx);

	return 0;
}

static int
eth_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	dev->data->rx_queue_state[rx_queue_id] = RTE_ETH_QUEUE_STATE_STARTED;
	return 0;
}

static int
eth_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
	dev->data->tx_queue_state[tx_queue_id] = RTE_ETH_QUEUE_STATE_STARTED;
	return 0;
}

static int
eth_rx_queue_stop(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	dev->data->rx_queue_state[rx_queue_id] = RTE_ETH_QUEUE_STATE_STOPPED;
	return 0;
}
static int
eth_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
	dev->data->tx_queue_state[tx_queue_id] = RTE_ETH_QUEUE_STATE_STOPPED;
	return 0;
}
static const struct eth_dev_ops ops = {
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_close = eth_dev_close,
	.dev_configure = eth_dev_configure,
	.dev_infos_get = eth_dev_info,
	.rx_queue_setup = eth_rx_queue_setup,
	.tx_queue_setup = eth_tx_queue_setup,
	.rx_queue_start = eth_rx_queue_start,
	.tx_queue_start = eth_tx_queue_start,
	.rx_queue_stop = eth_rx_queue_stop,
	.tx_queue_stop = eth_tx_queue_stop,
	.link_update = eth_link_update,
#if 0
	.rx_queue_release = eth_queue_release,
	.tx_queue_release = eth_queue_release,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
#endif	
};

static int fetch_id_from_map(char *value) {
	struct bpf_map_info info = {0};
	uint32_t id = 0;
	int err = 0, fd = 0, len = sizeof(info);

    while (1) {
		err = bpf_map_get_next_id(id, &id);
		if (err)
			break;

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0)
			break;

		err = bpf_obj_get_info_by_fd(fd, &info, &len);
		if (err)
			break;

		PMD_LOG(DEBUG, " obj - fd (%d) id (%u) name (%s)\n", fd, info.id, info.name);
		if (strncmp(info.name, (char *)value, strlen((char *)value)) == 0) {
			return info.id;
		}
	}

	return 0;
}

/*
 * share xskx_map id
 */
static inline int
select_xskx_map(const uint8_t *key, const uint8_t *value, void *extra_args)
{
	if (extra_args && value) 
		strlcpy(extra_args, value, ETH_XDP_ARG_MAXLEN);
	
	PMD_LOG(ERR, "lookup for (%s)!", (char *)extra_args);

	return 0;
}

/*
 * share interface
 */
static inline int
select_kern_iface(const uint8_t *key, const uint8_t *value, void *extra_args)
{
	const uint8_t *kiface = value;
	struct pmd_devargs *xdp_kiface = extra_args; 

	if (!xdp_kiface || !kiface) 
		return -1;	

	strlcpy(xdp_kiface, kiface, ETH_XDP_ARG_MAXLEN);

	return 0;
}

/*
 * share queue interface
 */
static inline int
select_ifaceq(const uint8_t *key, const uint8_t *value, void *extra_args)
{
	if ((value == NULL) || (extra_args == NULL))
		return -1;

	memset(extra_args, value, sizeof(int32_t));
	if (*(int32_t *)extra_args != 0) {
		PMD_LOG(ERR, "queue 0 is only supported, current queue (%d)!", *(int32_t *)extra_args);
		return -2;
	}

	return 0;
}

/*
 * share offset for meta-data
 */
static inline int
select_metdata_offset(const uint8_t *key, const uint8_t *value, void *extra_args)
{
	if ((value == NULL) || (extra_args == NULL))
		return -1;

	*(uint32_t *)extra_args = atoi(value);

	return 0;
}

static int
pmd_xdpzc_probe(struct rte_vdev_device *dev)
{
	const uint8_t *name;
	uint32_t is_rx_pcap = 0, is_tx_pcap = 0;
	struct rte_kvargs *kvlist;
	struct pmd_devargs xsks = {0};
	struct pmd_devargs dumpers = {0};
	struct rte_eth_dev *eth_dev =  NULL;
	struct pmd_internals *internal;
	int single_iface = 0;
	int ret;

	name = rte_vdev_device_name(dev);
	PMD_LOG(INFO, "Initializing pmd_xdpzc (%s) on numa socket %d", name, rte_socket_id());

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		PMD_LOG(ERR, "failure (%s) not supported in secondary!", name);
			return -EPERM;
	}

	kvlist = rte_kvargs_parse(rte_vdev_device_args(dev),
				valid_arguments);
	if (kvlist == NULL)
		return -1;

	xsks.k_iface_name[0] = '\0';
	xsks.bpf_path[0]    = '\0';
	xsks.data_offset = 256;		/* XDP HeadRoom */	
	xsks.kiface_q    = 0;
	xsks.xskx_map[0] = '\0';
	xsks.xskx_map_id = -1;

	/*
	 * If iface argument is passed we open the NICs and use them for
	 * reading / writing
	 */
	ret = rte_kvargs_count(kvlist, ETH_XDP_KIFACE_ARG);
	if (ret != 1) {
		PMD_LOG(ERR, "insufficent arguments (%d)!\n", ret);
		goto free_kvlist;
	}

	ret = rte_kvargs_process(kvlist, ETH_XDP_KIFACE_ARG,
			&select_kern_iface, &xsks.k_iface_name);
	if (ret < 0)
		goto free_kvlist;

	ret = rte_kvargs_process(kvlist, ETH_XDP_KIFACE_Q_ARG,
			&select_ifaceq, &xsks.xskx_map);
	if (ret < 0)
		goto free_kvlist;

	ret = rte_kvargs_process(kvlist, ETH_XDP_XSKX_MAP,
			&select_xskx_map, &xsks.xskx_map);
	if (ret < 0)
		goto free_kvlist;

	ret = rte_kvargs_process(kvlist, ETH_XDP_DATA_OFFSET,
			&select_metdata_offset, &xsks.data_offset);
	if (ret < 0)
		goto free_kvlist;

	xsks.xskx_map_id = fetch_id_from_map(xsks.xskx_map);

	xsks.xsk_fd = socket(PF_XDP, SOCK_RAW, 0);
	if (xsks.xsk_fd < 0) {  
		PMD_LOG(ERR, "Failed to open PF_XDP socket [%d]", xsks.xsk_fd);
		return -1;
	}	

	PMD_LOG(INFO, " iface %s queue %d data_offset %d, BPF MAP (%s) (%d)\n", 
			xsks.k_iface_name, xsks.kiface_q, xsks.data_offset, xsks.xskx_map, xsks.xskx_map_id);
	{ 
		struct pmd_internals *internals = NULL; 
		struct rte_eth_dev_data *data;
		struct pmd_process_private *pp;

		PMD_LOG(INFO, "Creating BPF!");

		pp = (struct pmd_process_private *)
			rte_zmalloc(NULL, sizeof(struct pmd_process_private),
					RTE_CACHE_LINE_SIZE);
		if (pp == NULL) {
			PMD_LOG(ERR,
				"Failed to allocate memory for process private!\n");
			return -1;
		}

		/* reserve an ethdev entry */ 
		eth_dev = rte_eth_vdev_allocate(dev, sizeof(*internals)); 
		if (!eth_dev) {
			rte_free(pp); 
			return -1;
		}
		eth_dev->process_private = pp;
		/* now put it all together
		 * - store queue data in internals,
		 * - store numa_node info in eth_dev
		 * - point eth_dev_data to internals
		 * - and point eth_dev structure to new eth_dev_data structure
		 */
		internals = eth_dev->data->dev_private;
		
		data = eth_dev->data;

		data->nb_rx_queues = (uint16_t)0x1;
		data->nb_tx_queues = (uint16_t)0x1;

		internals->eth_addr = (struct ether_addr) {
			.addr_bytes = { 0x02, 0x70, 0x63, 0x61, 0x70, 0x01 }
		};
		data->dev_link = pmd_link;
		data->mac_addrs = &(internals->eth_addr);

		/*
		 * NOTE: we'll replace the data element, of originally allocated
		 * eth_dev so the rings are local per-process
		 */
		eth_dev->dev_ops = &ops;
#if  MBUF_ZC
		eth_dev->rx_pkt_burst = eth_xdp_full_zc_rx;
		eth_dev->tx_pkt_burst = eth_xdp_full_zc_tx;
#else
		eth_dev->rx_pkt_burst = eth_xdp_zc_rx;
		eth_dev->tx_pkt_burst = eth_xdp_zc_tx;
#endif

		strlcpy(internals->devargs, rte_vdev_device_args(dev),
				ETH_XDP_ARG_MAXLEN);
		rte_memcpy(&(internals->priv_data), &xsks, sizeof(struct pmd_devargs));

	}
	rte_eth_dev_probing_finish(eth_dev);

	return 0;

free_kvlist:
	rte_kvargs_free(kvlist);

	return ret;
}

static int
pmd_xdpzc_remove(struct rte_vdev_device *dev)
{
	struct pmd_internals *internals = NULL;
	struct rte_eth_dev *eth_dev = NULL;

	PMD_LOG(INFO, "Closing ethdev on numa socket %d\n",
			rte_socket_id());

	if (!dev)
		return -1;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		PMD_LOG(ERR, "failure not supported in secondary!\n");
			return -EPERM;
	}

	/* reserve an ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(dev));
	if (eth_dev == NULL)
		return -1;

	internals = (struct pmd_internals *) eth_dev->data->dev_private;

	/* Close the XDP socket */
    int ret = close(internals->priv_data.xsk_fd);
    if (ret != 0)
    	PMD_LOG(ERR, "Error closing xdp socket [%d]\n", ret);

	rte_free(eth_dev->process_private);
	rte_eth_dev_release_port(eth_dev);

	return 0;
}

static struct rte_vdev_driver pmd_xdpzc_drv = {
	.probe = pmd_xdpzc_probe,
	.remove = pmd_xdpzc_remove,
};

RTE_PMD_REGISTER_VDEV(net_xdpzc, pmd_xdpzc_drv);
RTE_PMD_REGISTER_ALIAS(net_xdpzc, eth_xdpzc);
RTE_PMD_REGISTER_PARAM_STRING(net_xdpzc,
	ETH_XDP_KIFACE_ARG "=<ifc> "
	ETH_XDP_KIFACE_Q_ARG "=<ifc> "
	ETH_XDP_DATA_OFFSET  "=<int> "
	ETH_XDP_XSKX_MAP "=<string>");

RTE_INIT(eth_xdpzc_init_log)
{
	eth_xdpzc_logtype = rte_log_register("pmd.net.xdpzc");
	if (eth_xdpzc_logtype >= 0)
		rte_log_set_level(eth_xdpzc_logtype, RTE_LOG_NOTICE);
}
