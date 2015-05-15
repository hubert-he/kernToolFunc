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
											=> tcp_create_openreq_child // 派生出新的sock并赋值，继承request_sock, 初始化滑动窗口等
											=> __inet_hash_nolisten // hashinfo->ehash,添加到established
											=> __inet_inherit_port // icsk_bind_hash & hashinfo->bhash数组
										=> inet_csk_reqsk_queue_unlink // 从icsk_accept_queue.listen_opt摘下
										=> inet_csk_reqsk_queue_add // 添加到icsk_accept_queue.rksq_accept_head中去
									=> tcp_child_process
										=> tcp_rcv_state_process// 在这里，初始化拥塞控制，当然编译之前配置好拥塞控制算法
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
										=> mss_now = tcp_send_mss(sk, &size_goal, flags); // 确定size_goal
										=> iovlen = msg->msg_iovlen;iov = msg->msg_iov; // 确定待传输数据位置 
										=> skb = sk_stream_alloc_skb(); // 根据空间的需要决定是否分配new skb
										=> skb_entail(sk, skb);// put skb in sk->sk_write_queue & sk->sk_send_head
										=> sk_stream_alloc_page(sk) // 分配页，sk->sk_sndmsg_page, sk->sk_sndmsg_off,skb_shinfo(skb)->nr_frags(一个skb所载的page是有限的MAX_SKB_FRAGS)
										=> skb_copy_to_page // 拷贝user数据到page
										=> tcp_push(sk, flags, mss_now, tp->nonagle); // 发送
											=> __tcp_push_pending_frames
												=> tcp_write_xmit(sk, cur_mss, nonagle, 0, GFP_ATOMIC)
													=> tcp_transmit_skb(sk, skb, 1, gfp);
														=> skb_push(skb, tcp_header_size);// 预留skb->data作为TCP Header
														=> skb_set_owner_w(skb, sk);// 关联skb 和 sk
														=> // 构造TCP Header
														=> tcp_event_ack_sent(sk, tcp_skb_pcount(skb));/*如果带ACK*/
														=> tcp_event_data_sent(tp, skb, sk);
														=> err = icsk->icsk_af_ops->queue_xmit(skb, 0);// ip_queue_xmit 发送到IP层
													=> tcp_event_new_data_sent(sk, skb);// 更新sk发送状态，准备发送下一个skb
													=> tcp_minshall_update(tp, mss_now, skb);// small packet 统计
													
	ACK: 8ea98b79:9354d0c1
	====================================>
							tcp_v4_rcv
								=> tcp_hdr // 拿到头部
								=> __inet_lookup_skb // 查找skb对应的sk
								=>sock_owned_by_user
								=> tcp_prequeue // 由sysctl_tcp_low_latency决定是否使用
								=> tcp_v4_do_rcv / sk_add_backlog // tcp_v4_do_rcv 核心处理
									=> tcp_rcv_established
	
	DATA: 8ea98b79:9354d0c1
	====================================>
	
	==========================
								主进程唤醒，执行recv
							sys_recv =>sys_recvfrom
								=> sock_recvmsg(sock, &msg, size, flags);
									=> __sock_recvmsg(&iocb, sock, msg, size, flags);
										=> sock->ops->recvmsg(iocb, sock, msg, size, flags) // sock_common_recvmsg 统一的处理
											=> sk->sk_prot->recvmsg() // tcp_recvmsg
											
								
								
								
tcp_prequeue  wake_up_interruptible		
tcp_sendmsg sk_stream_wait_connect	


Source Port		:	th->source = inet->sport;
Destination Port:	th->dest   = inet->dport;
Seqence Number	:	th->seq	   = htonl(tcb->seq);
Ack Number		:	th->ack_seq = htonl(tp->rcv_nxt);
Data Offset		:	((tcp_header_size >> 2) << 12)
Flags			:	tcb->flags
Window			:	th->window = htons(min(tp->rcv_wnd, 65535U)) 或者 th->window = htons(tcp_select_window(sk)); 
					<= 注意如果开启了window_scale 此域表示除以window scale后的值
					<= newwin值确定:
						1. tcp_receive_window(rcv_wnd,rcv_nxt,rcv_wup)
						2. __tcp_select_window(tp->window_clamp,sk->sk_rcvbuf,sk->sk_rmem_alloc,tp->rcv_ssthresh)
						3. 关于tp->rcv_ssthresh的赋值
						服务端：tcp_select_initial_window(&req->rcv_wnd)//收到SYN后 tcp_make_synack <- __tcp_v4_send_synack <- tcp_v4_conn_request
								tp->rcv_ssthresh = req->rcv_wnd; 
								以上window_clamp也是如此
Checksum		:	icsk->icsk_af_ops->send_check(sk, skb->len, skb);
Urgent Pointer	:
Options			:	tcp_options_write
Padding			:	tcp_options_write


tcb->seq: 是待发送skb的sequence Number
tp->write_seq: tcb_seq+1
tp->snd_up: 非含OutBand Data， snd_up 保持与第一个tcp 数据报文seqence Number不变
					