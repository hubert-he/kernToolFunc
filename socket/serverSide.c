192.168.1.14				192.168.1.1
		======================
								主进程执行listen
							sys_listen
								=> sockfd_lookup_light
								=> inet_listen
									=> inet_csk_listen_start
										=> reqsk_queue_alloc(&icsk->icsk_accept_queue, nr_table_entries)// nr_table_entries就是backlog
										=> inet_csk_delack_init// delay ack initial
										=> sk->sk_state = TCP_LISTEN
										=> inet_csk_get_port // 申请端口
									=> sk->sk_max_ack_backlog = backlog;
SYN: 992bb6a7:00000000
	=========================>
							tcp_v4_rcv
								=> tcp_hdr // 拿到头部
								=> __inet_lookup_skb // 查找skb对应的sk
								=>sock_owned_by_user
								=> tcp_prequeue // 由sysctl_tcp_low_latency决定是否使用
								=> tcp_v4_do_rcv / sk_add_backlog // tcp_v4_do_rcv 核心处理
									=> tcp_v4_hnd_req
										=> inet_csk_search_req // 查找是否已经在半连接队列icsk->icsk_accept_queue.listen_opt
										=> inet_lookup_established // 查找是否是已经建立连接的 tcp_hashinfo.ehash里找
									=> tcp_rcv_state_process
										=> tcp_v4_conn_request
											=> inet_csk_reqsk_queue_is_full // icsk_accept_queue
											=> sk_acceptq_is_full //sk->sk_ack_backlog
											=> inet_reqsk_alloc
											=> tcp_v4_init_sequence// 初始化 seqence number
											=> __tcp_v4_send_synack // send syn_ack
											=> inet_csk_reqsk_queue_hash_add //链入icsk->icsk_accept_queue
	<=========================							
								SYN+ACK: 76738eb3:992bb6a8
ACK: 992bb6a8:76738eb4
	=========================>	
							tcp_v4_rcv
								=> tcp_hdr // 拿到头部
								=> __inet_lookup_skb // 查找skb对应的sk
								=>sock_owned_by_user
								=> tcp_prequeue // 由sysctl_tcp_low_latency决定是否使用
								=> tcp_v4_do_rcv / sk_add_backlog // tcp_v4_do_rcv 核心处理
									=> tcp_v4_hnd_req
										=> inet_csk_search_req // 查找是否已经在半连接队列icsk->icsk_accept_queue.listen_opt
									=> tcp_check_req // defer_accept 在此处返回NULL
										=> tcp_v4_syn_recv_sock
											=> tcp_create_openreq_child // 派生出新的sock并赋值
											=> __inet_hash_nolisten // hashinfo->ehash,添加到established
											=> __inet_inherit_port // icsk_bind_hash & hashinfo->bhash数组
										=> inet_csk_reqsk_queue_unlink // 从icsk_accept_queue.listen_opt摘下
										=> inet_csk_reqsk_queue_add // 添加到icsk_accept_queue.rksq_accept_head中去
									=> tcp_child_process
										=> tcp_rcv_state_process
											=> tcp_ack // 判断此ack 调整tcp参数
											=> tcp_set_state(sk, TCP_ESTABLISHED)
											=> sock_def_wakeup // 唤醒进程
											=> sk_wake_async(sk,SOCK_WAKE_IO, POLL_OUT)
											=> tcp_init_buffer_space
											=> tcp_fast_path_on
		======================
								主进程唤醒，执行accept
							sys_accept
								=> sockfd_lookup_light // 查找监听socket
								=> sock_alloc // 分配socket结构体，注不是sock
								=> inet_accept // 
									=> inet_csk_accept
										=> reqsk_queue_get_child //从icsk->icsk_accept_queue获得Established sock 
	<=========================							
								DATA: 76738eb4:992bb6a8
							sock_sendmsg
								=> __sock_sendmsg
									=> tcp_sendmsg
								
								
								
								
								
tcp_prequeue  wake_up_interruptible		
tcp_sendmsg sk_stream_wait_connect						