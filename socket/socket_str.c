struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;
#define sk_node			__sk_common.skc_node
#define sk_nulls_node		__sk_common.skc_nulls_node//@skc_nulls_node: main hash linkage for UDP/UDP-Lite protocol sk->sk_prot->hash(sk);(inet_csk_listen_start[inet_hash])
#define sk_refcnt		__sk_common.skc_refcnt //@skc_refcnt: reference count  atomic_set(&sk->sk_refcnt, 1);  sock_init_data

#define sk_copy_start		__sk_common.skc_hash
#define sk_hash			__sk_common.skc_hash
#define sk_family		__sk_common.skc_family// @skc_family: network address family(sk_alloc) 例如 PF_INET
#define sk_state		__sk_common.skc_state //@skc_state: Connection state  sk->sk_state = TCP_CLOSE;  sk->sk_state = TCP_CLOSE;(sock_init_data)  tcp_v4_init_sock
#define sk_reuse		__sk_common.skc_reuse// @skc_reuse: %SO_REUSEADDR setting
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
#define sk_bind_node		__sk_common.skc_bind_node
#define sk_prot			__sk_common.skc_prot // @skc_prot: protocol handlers inside a network family  sk->sk_prot = sk->sk_prot_creator = prot;(sk_alloc) 例如tcp协议下，prot为tcp_prot
#define sk_net			__sk_common.skc_net
	kmemcheck_bitfield_begin(flags);
	unsigned int		sk_shutdown  : 2,
				sk_no_check  : 2, // @sk_no_check: %SO_NO_CHECK setting, wether or not checkup packets  sk->sk_no_check = answer_no_check;(inet_create)
				sk_userlocks : 4,
				sk_protocol  : 8, //@sk_protocol: which protocol this socket belongs in this network family, 例如 IPPROTO_TCP sk->sk_protocol = protocol;  inet_create
				sk_type      : 16;// @sk_type: socket type (%SOCK_STREAM, etc) 与socket下sock->type 对应(sock_init_data)
	kmemcheck_bitfield_end(flags);
	int			sk_rcvbuf;// @sk_rcvbuf: size of receive buffer in bytes  sk->sk_rcvbuf = sysctl_rmem_default;(sock_init_data)
	socket_lock_t		sk_lock;
	/*
	 * The backlog queue is special, it is always used with
	 * the per-socket spinlock held and requires low latency
	 * access. Therefore we special case it's implementation.
	 */
	struct {
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	wait_queue_head_t	*sk_sleep;// @sk_sleep: sock wait queue 与socket下wait 对应 sk->sk_sleep = &sock->wait;(sock_init_data)
	struct dst_entry	*sk_dst_cache;//@sk_dst_cache: destination cache sk_dst_reset(sk);(inet_csk_listen_start)
#ifdef CONFIG_XFRM
	struct xfrm_policy	*sk_policy[2];
#endif
	rwlock_t		sk_dst_lock;// @sk_dst_lock: destination cache lock (sock_init_data)
	atomic_t		sk_rmem_alloc;
	atomic_t		sk_wmem_alloc;
	atomic_t		sk_omem_alloc;
	int			sk_sndbuf;// @sk_sndbuf: size of send buffer in bytes  与全局变量sysctl_rmem_default 相关  sk->sk_sndbuf=sysctl_wmem_default;(sock_init_data)
	struct sk_buff_head	sk_receive_queue;//@sk_receive_queue: incoming packets  skb_queue_head_init(&sk->sk_receive_queue);(sock_init_data)
	struct sk_buff_head	sk_write_queue;//@sk_write_queue: Packet sending queue  skb_queue_head_init(&sk->sk_write_queue);(sock_init_data)
#ifdef CONFIG_NET_DMA
	struct sk_buff_head	sk_async_wait_queue;
#endif
	int			sk_wmem_queued;
	int			sk_forward_alloc;
	gfp_t			sk_allocation;//@sk_allocation: allocation mode sk->sk_allocation = GFP_KERNEL;(sock_init_data)
	int			sk_route_caps;
	int			sk_gso_type;
	unsigned int		sk_gso_max_size;
	int			sk_rcvlowat;//@sk_rcvlowat: %SO_RCVLOWAT setting   sk->sk_rcvlowat     =   1;  sock_init_data
	unsigned long sk_flags;// @sk_flags: %SO_LINGER (l_onoff), %SO_BROADCAST, %SO_KEEPALIVE, %SO_OOBINLINE settings, %SO_TIMESTAMPING settings  sock_set_flag(sk, SOCK_ZAPPED);(sock_init_data)
	unsigned long	        sk_lingertime;
	struct sk_buff_head	sk_error_queue;//@sk_error_queue: rarely used  skb_queue_head_init(&sk->sk_error_queue);(sock_init_data)
	struct proto		*sk_prot_creator;
	rwlock_t		sk_callback_lock;//@sk_callback_lock: used with the callbacks in the end of this struct
	int			sk_err,
				sk_err_soft;
	atomic_t		sk_drops;//@sk_drops: raw/udp drops counter  atomic_set(&sk->sk_drops, 0); sock_init_data
	unsigned short		sk_ack_backlog;// @sk_ack_backlog: current listen backlog  sk->sk_ack_backlog = 0;(inet_csk_listen_start)
	unsigned short		sk_max_ack_backlog;//@sk_max_ack_backlog: listen backlog set in listen() sk->sk_max_ack_backlog = 0;(inet_csk_listen_start)  sk->sk_max_ack_backlog = backlog;(inet_listen) 
	__u32			sk_priority;
	struct ucred		sk_peercred;//@sk_peercred: %SO_PEERCRED setting sk->sk_peercred.pid = 0;sk->sk_peercred.uid = -1;sk->sk_peercred.gid = -1;  sock_init_data
	long			sk_rcvtimeo;//@sk_rcvtimeo: %SO_RCVTIMEO setting  sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;(sock_init_data)
	long			sk_sndtimeo;//@sk_sndtimeo: %SO_SNDTIMEO setting sk->sk_sndtimeo     =   MAX_SCHEDULE_TIMEOUT;   sock_init_data
	struct sk_filter      	*sk_filter;
	void			*sk_protinfo;
	struct timer_list	sk_timer;//@sk_timer: sock cleanup timer init_timer(&sk->sk_timer);(sock_init_data)
	ktime_t			sk_stamp;//@sk_stamp: time stamp of last packet received  sk->sk_stamp = ktime_set(-1L, 0);  sock_init_data
	struct socket		*sk_socket;//@sk_socket: Identd and reporting IO signals, 反向指向 socket结构体 sk_set_socket(sk, sock);(sock_init_data)
	void			*sk_user_data;
	struct page		*sk_sndmsg_page;// @sk_sndmsg_page: cached page for sendmsg  sk->sk_sndmsg_page  =   NULL;  sock_init_data
	struct sk_buff		*sk_send_head;//@sk_send_head: front of stuff to transmit  sk->sk_send_head = NULL;(sock_init_data)
	__u32			sk_sndmsg_off;//@sk_sndmsg_off: cached offset for sendmsg   sk->sk_sndmsg_off = 0;  sock_init_data
	int			sk_write_pending;//@sk_write_pending: a write to stream socket waits to start  sk->sk_write_pending =   0; sock_init_data
#ifdef CONFIG_SECURITY
	void			*sk_security;
#endif
	__u32			sk_mark;
	/* XXX 4 bytes hole on 64 bit */
	void			(*sk_state_change)(struct sock *sk);// @sk_state_change: callback to indicate change in the state of the sock sk->sk_state_change=sock_def_wakeup;(sock_init_data)
	void			(*sk_data_ready)(struct sock *sk, int bytes);// @sk_data_ready: callback to indicate there is data to be processed sk->sk_data_ready=sock_def_readable;(sock_init_data)
	void			(*sk_write_space)(struct sock *sk); //@sk_write_space: callback to indicate there is bf sending space available  sk->sk_write_space = sk_stream_write_space; tcp_v4_init_sock
	void			(*sk_error_report)(struct sock *sk);// @sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE) sk->sk_write_space = sock_def_write_space;(sock_init_data) sk->sk_error_report = sock_def_error_report;(sock_init_data)
  	int	 (*sk_backlog_rcv)(struct sock *sk,	struct sk_buff *skb);// @sk_backlog_rcv: callback to process the backlog  sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;  inet_create  
	void (*sk_destruct)(struct sock *sk);// @sk_destruct: called at sock freeing time, i.e. when all refcnt == 0;  sk->sk_destruct = sock_def_destruct;(sock_init_data) sk->sk_destruct = inet_sock_destruct(inet_create)
}
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	__be32			daddr;
	__be32			rcv_saddr;
	__be16			dport;
	__u16			num;//@num - Local port   
	__be32			saddr;
	__s16			uc_ttl;//inet->uc_ttl = -1;  inet_create
	__u16			cmsg_flags;
	struct ip_options_rcu	*inet_opt;
	__be16			sport;
	__u16			id; //@id - ID counter for DF pkts  inet->id = 0;(inet_create)
	__u8			tos;
	__u8			mc_ttl;//@mc_ttl - Multicasting TTL   inet->mc_ttl  = 1;   inet_create
	__u8			pmtudisc;//猜测:MTU探测相关 ipv4_config.no_pmtu_disc相关下初始化(inet_create)
	__u8			recverr:1,
				is_icsk:1, //@is_icsk - is this an inet_connection_sock?  inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;(inet_create)
				freebind:1,
				hdrincl:1,
				mc_loop:1, // inet->mc_loop   = 1;  inet_create
				transparent:1,
				mc_all:1;
	int			mc_index;//@mc_index - Multicast device index  inet->mc_index  = 0;   inet_create
	__be32			mc_addr;
	struct ip_mc_socklist	*mc_list;//@mc_list - Group array  inet->mc_list   = NULL;  inet_create
	struct {
		unsigned int		flags;
		unsigned int		fragsize;
		struct ip_options	*opt;
		struct dst_entry	*dst;
		int			length; /* Total length of all frames */
		__be32			addr;
		struct flowi		fl;
	} cork;
}
struct inet_connection_sock {
	/* inet_sock has to be the first member! */
	struct inet_sock	  icsk_inet;
	struct request_sock_queue icsk_accept_queue;//@icsk_accept_queue:FIFO of established children int rc = reqsk_queue_alloc(&icsk->icsk_accept_queue, nr_table_entries);(inet_csk_listen_start)
	struct inet_bind_bucket	  *icsk_bind_hash;
	unsigned long		  icsk_timeout;
 	struct timer_list	  icsk_retransmit_timer;
 	struct timer_list	  icsk_delack_timer;
	__u32			  icsk_rto; //@icsk_rto: Retransmit timeout  icsk->icsk_rto = TCP_TIMEOUT_INIT;  tcp_v4_init_sock
	__u32			  icsk_pmtu_cookie;
	const struct tcp_congestion_ops *icsk_ca_ops; //@icsk_ca_ops Pluggable congestion control hook  icsk->icsk_ca_ops = &tcp_init_congestion_ops; tcp_v4_init_sock
	const struct inet_connection_sock_af_ops *icsk_af_ops;
	unsigned int		  (*icsk_sync_mss)(struct sock *sk, u32 pmtu);
	__u8			  icsk_ca_state;
	__u8			  icsk_retransmits;
	__u8			  icsk_pending;
	__u8			  icsk_backoff;
	__u8			  icsk_syn_retries;
	__u8			  icsk_probes_out;
	__u16			  icsk_ext_hdr_len;
	struct {
		__u8		  pending;	 /* ACK is pending			   */
		__u8		  quick;	 /* Scheduled number of quick acks	   */
		__u8		  pingpong;	 /* The session is interactive		   */
		__u8		  blocked;	 /* Delayed ACK was blocked by socket lock */
		__u32		  ato;		 /* Predicted tick of soft clock	   */
		unsigned long	  timeout;	 /* Currently scheduled timeout		   */
		__u32		  lrcvtime;	 /* timestamp of last received data packet */
		__u16		  last_seg_size; /* Size of last incoming segment	   */
		__u16		  rcv_mss;	 /* MSS used for delayed ACK decisions	   */ 
	} icsk_ack;//@icsk_ack:Delayed ACK control data  inet_csk_delack_init(sk);(inet_listen_start)清零
	struct {
		int		  enabled;

		/* Range of MTUs to search */
		int		  search_high;
		int		  search_low;

		/* Information on the current probe. */
		int		  probe_size;
	} icsk_mtup;
	u32			  icsk_ca_priv[16];
#define ICSK_CA_PRIV_SIZE	(16 * sizeof(u32))
}
struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	u16	xmit_size_goal_segs; /* Goal for segmenting output packets */

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
 	u32	rcv_nxt;	/* What we want to receive next 	*/
	u32	copied_seq;	/* Head of yet unread data		*/
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
 	u32	snd_nxt;	/* Next sequence we send		*/

 	u32	snd_una;	/* First byte we want an ack for	*/
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */

	/* Data for direct copy to user */
	struct {
		struct sk_buff_head	prequeue;
		struct task_struct	*task;
		struct iovec		*iov;
		int			memory;
		int			len;
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

	u32	snd_wl1;	/* Sequence for window update		*/
	u32	snd_wnd;	/* The window we expect to receive	*/
	u32	max_window;	/* Maximal window ever seen from peer	*/
	u32	mss_cache;	/* Cached effective mss, not including SACKS tp->mss_cache = 536; tcp_v4_init_sock*/

	u32	window_clamp;	/* Maximal window to advertise		*/
	u32	rcv_ssthresh;	/* Current window clamp			*/

	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	u16	advmss;		/* Advertised MSS			*/
	u8	frto_counter;	/* Number of new acks after RTO */
	u8	nonagle;	/* Disable Nagle algorithm?             */

/* RTT measurement */
	u32	srtt;		/* smoothed round trip time << 3	*/
	u32	mdev;		/* medium deviation	 tp->mdev = TCP_TIMEOUT_INIT; 	tcp_v4_init_sock	*/
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	u32	rttvar;		/* smoothed mdev_max			*/
	u32	rtt_seq;	/* sequence number to update rttvar	*/

	u32	packets_out;	/* Packets which are "in flight"	*/
	u32	retrans_out;	/* Retransmitted packets out		*/

	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	ecn_flags;	/* ECN status bits.			*/
	u8	reordering;	/* Packet reordering metric. tp->reordering = sysctl_tcp_reordering; tcp_v4_init_sock	*/
	u32	snd_up;		/* Urgent pointer		*/

	u8	keepalive_probes; /* num of allowed keep alive probes	*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH; 	tcp_v4_init_sock*/
 	u32	snd_cwnd;	/* Sending congestion window	tp->snd_cwnd = 2;   tcp_v4_init_sock	*/
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this  tp->snd_cwnd_clamp = ~0; tcp_v4_init_sock*/
	u32	snd_cwnd_used;
	u32	snd_cwnd_stamp;

 	u32	rcv_wnd;	/* Current receiver window		*/
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	u32	lost_out;	/* Lost packets			*/
	u32	sacked_out;	/* SACK'd packets			*/
	u32	fackets_out;	/* FACK'd packets			*/
	u32	tso_deferred;
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */

	/* from STCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;
	struct sk_buff *scoreboard_skb_hint;
	struct sk_buff *retransmit_skb_hint;

	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */

	/* SACKs data, these 2 need to be together (see tcp_build_and_update_options) */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct tcp_sack_block recv_sack_cache[4];

	struct sk_buff *highest_sack;   /* highest skb with SACK received
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */

	int     lost_cnt_hint;
	u32     retransmit_high;	/* L-bits may be on up to this seqno */

	u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */

	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	u32	undo_marker;	/* tracking retrans started here. */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	total_retrans;	/* Total retransmits for entire connection */

	u32	urg_seq;	/* Seq of received urgent pointer */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */

	int			linger2;

/* Receiver side RTT estimation */
	struct {
		u32	rtt;
		u32	seq;
		u32	time;
	} rcv_rtt_est;

/* Receiver queue space */
	struct {
		int	space;
		u32	seq;
		u32	time;
	} rcvq_space;

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	const struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signature Option information */
	struct tcp_md5sig_info	*md5sig_info;
#endif
}

// TCP的定时器   tcp_init_xmit_timers
1. 连接建立   75s							由重传合并
2. 重传		  由往返时间和已重传次数决定	inet_csk_init_xmit_timers
3. 延迟ACK	  200ms							inet_csk_init_xmit_timers
4. persist定时器(0窗口通告)
5. keepAlive定时器   2hour   				inet_csk_init_xmit_timers
6. FIN_WAIT_2定时器  10min + 75s
7. TIME_WAIT定时器   2MSL



TCP与IP函数接口点
connect:
	struct dst_entry 
	ip_route_connect 确定目的地址是否可达
	ip_rt_put  清除路由选项
	rt_get_peer  tcp_v4_connect时候查找
	ip_route_newports 查找完sport后重新刷新路由选项
	dst_metric   获得mtu等信息
	
	sk_setup_caps
	inet_csk_route_req
	ip_build_and_send_pkt
	
	
各种结构包含
tcp_sock
	=>inet_connection_sock
		=> inet_sock
			=> sock
			
			

space的确定
sysctl_tcp_adv_win_scale <= 0
	space = sk_rcvbuf/2^|sysctl_tcp_adv_win_scale|
sysctl_tcp_adv_win_scale > 0
	space = sk_rcvbuf - sk_rcvbuf / 2^sysctl_tcp_adv_win_scale
	
space = (space / mss) * mss

sysctl_tcp_window_scaling > 0 // enable window scale
	rcv_wscale=log2(max(sysctl_tcp_rmem[2],sysctl_rmem_max))
	rcv_wscale ~ [0,14)
sysctl_tcp_window_scaling = 0
	rcv_wscale = 0
	
tp->window_clamp = 65535 * 2^rcv_wscale => [65535, 1G)

rcv_wnd的确定
与mss、rcv_wscale、space共同决定
if (mss > (1 << *rcv_wscale)) 
{// 1 << *rcv_wscale [0, 8192]
		int init_cwnd = 4;
		if (mss > 1460 * 3)
			init_cwnd = 2;
		else if (mss > 1460)
			init_cwnd = 3;
		if (*rcv_wnd > init_cwnd * mss)
			*rcv_wnd = init_cwnd * mss;
		else
			*rcv_wnd = space;
}
else
	rcv_wnd = space // 可见此时rcv_wscale比较大 已经接近11->14
			
tp->rx_opt.rcv_wscale = rcv_wscale;
tp->rcv_wnd = rcv_wnd;
tp->window_clamp=window_clamp;
tp->rcv_ssthresh = tp->rcv_wnd;