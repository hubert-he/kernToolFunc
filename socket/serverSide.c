192.168.1.14				192.168.1.1
		======================
								������ִ��listen
							sys_listen
								=> sockfd_lookup_light
								=> inet_listen
									=> inet_csk_listen_start
										=> reqsk_queue_alloc(&icsk->icsk_accept_queue, nr_table_entries)// nr_table_entries����backlog
										=> inet_csk_delack_init// delay ack initial
										=> sk->sk_state = TCP_LISTEN
										=> inet_csk_get_port // ����˿�
									=> sk->sk_max_ack_backlog = backlog;
SYN: 992bb6a7:00000000
	=========================>
							tcp_v4_rcv
								=> tcp_hdr // �õ�ͷ��
								=> __inet_lookup_skb // ����skb��Ӧ��sk
								=>sock_owned_by_user
								=> tcp_prequeue // ��sysctl_tcp_low_latency�����Ƿ�ʹ��
								=> tcp_v4_do_rcv / sk_add_backlog // tcp_v4_do_rcv ���Ĵ���
									=> tcp_v4_hnd_req
										=> inet_csk_search_req // �����Ƿ��Ѿ��ڰ����Ӷ���icsk->icsk_accept_queue.listen_opt
										=> inet_lookup_established // �����Ƿ����Ѿ��������ӵ� tcp_hashinfo.ehash����
									=> tcp_rcv_state_process 
										=> tcp_v4_conn_request
											=> inet_csk_reqsk_queue_is_full // icsk_accept_queue
											=> sk_acceptq_is_full //sk->sk_ack_backlog
											=> inet_reqsk_alloc
											=> tcp_v4_init_sequence// ��ʼ�� seqence number
											=> __tcp_v4_send_synack // send syn_ack
											=> inet_csk_reqsk_queue_hash_add //����icsk->icsk_accept_queue
	<=========================							
								SYN+ACK: 76738eb3:992bb6a8
ACK: 992bb6a8:76738eb4
	=========================>	
							tcp_v4_rcv
								=> tcp_hdr // �õ�ͷ��
								=> __inet_lookup_skb // ����skb��Ӧ��sk
								=>sock_owned_by_user
								=> tcp_prequeue // ��sysctl_tcp_low_latency�����Ƿ�ʹ��
								=> tcp_v4_do_rcv / sk_add_backlog // tcp_v4_do_rcv ���Ĵ���
									=> tcp_v4_hnd_req
										=> inet_csk_search_req // �����Ƿ��Ѿ��ڰ����Ӷ���icsk->icsk_accept_queue.listen_opt
									=> tcp_check_req // defer_accept �ڴ˴�����NULL
										=> tcp_v4_syn_recv_sock
											=> tcp_create_openreq_child // �������µ�sock����ֵ���̳�request_sock, ��ʼ���������ڵ�
											=> __inet_hash_nolisten // hashinfo->ehash,��ӵ�established
											=> __inet_inherit_port // icsk_bind_hash & hashinfo->bhash����
										=> inet_csk_reqsk_queue_unlink // ��icsk_accept_queue.listen_optժ��
										=> inet_csk_reqsk_queue_add // ��ӵ�icsk_accept_queue.rksq_accept_head��ȥ
									=> tcp_child_process
										=> tcp_rcv_state_process// �������ʼ��ӵ�����ƣ���Ȼ����֮ǰ���ú�ӵ�������㷨
											=> tcp_ack // �жϴ�ack ����tcp����
											=> tcp_set_state(sk, TCP_ESTABLISHED)
											=> sock_def_wakeup // ���ѽ���
											=> sk_wake_async(sk,SOCK_WAKE_IO, POLL_OUT)
											=> tcp_init_buffer_space
											=> tcp_fast_path_on
		======================
								�����̻��ѣ�ִ��accept
							sys_accept
								=> sockfd_lookup_light // ���Ҽ���socket
								=> sock_alloc // ����socket�ṹ�壬ע����sock
								=> inet_accept // 
									=> inet_csk_accept
										=> reqsk_queue_get_child //��icsk->icsk_accept_queue���Established sock 
	<=========================							
								DATA: 76738eb4:992bb6a8
							sock_sendmsg
								=> __sock_sendmsg
									=> tcp_sendmsg
										=> mss_now = tcp_send_mss(sk, &size_goal, flags); // ȷ��size_goal
										=> iovlen = msg->msg_iovlen;iov = msg->msg_iov; // ȷ������������λ�� 
										=> skb = sk_stream_alloc_skb(); // ���ݿռ����Ҫ�����Ƿ����new skb
										=> skb_entail(sk, skb);// put skb in sk->sk_write_queue & sk->sk_send_head
										=> sk_stream_alloc_page(sk) // ����ҳ��sk->sk_sndmsg_page, sk->sk_sndmsg_off,skb_shinfo(skb)->nr_frags(һ��skb���ص�page�����޵�MAX_SKB_FRAGS)
										=> skb_copy_to_page // ����user���ݵ�page
										=> tcp_push(sk, flags, mss_now, tp->nonagle); // ����
											=> __tcp_push_pending_frames
												=> tcp_write_xmit(sk, cur_mss, nonagle, 0, GFP_ATOMIC)
													=> tcp_transmit_skb(sk, skb, 1, gfp);
														=> skb_push(skb, tcp_header_size);// Ԥ��skb->data��ΪTCP Header
														=> skb_set_owner_w(skb, sk);// ����skb �� sk
														=> // ����TCP Header
														=> tcp_event_ack_sent(sk, tcp_skb_pcount(skb));/*�����ACK*/
														=> tcp_event_data_sent(tp, skb, sk);
														=> err = icsk->icsk_af_ops->queue_xmit(skb, 0);// ip_queue_xmit ���͵�IP��
													=> tcp_event_new_data_sent(sk, skb);// ����sk����״̬��׼��������һ��skb
													=> tcp_minshall_update(tp, mss_now, skb);// small packet ͳ��
													
	ACK: 8ea98b79:9354d0c1
	====================================>
							tcp_v4_rcv
								=> tcp_hdr // �õ�ͷ��
								=> __inet_lookup_skb // ����skb��Ӧ��sk
								=>sock_owned_by_user
								=> tcp_prequeue // ��sysctl_tcp_low_latency�����Ƿ�ʹ��
								=> tcp_v4_do_rcv / sk_add_backlog // tcp_v4_do_rcv ���Ĵ���
									=> tcp_rcv_established
	
	DATA: 8ea98b79:9354d0c1
	====================================>
	
	==========================
								�����̻��ѣ�ִ��recv
							sys_recv =>sys_recvfrom
								=> sock_recvmsg(sock, &msg, size, flags);
									=> __sock_recvmsg(&iocb, sock, msg, size, flags);
										=> sock->ops->recvmsg(iocb, sock, msg, size, flags) // sock_common_recvmsg ͳһ�Ĵ���
											=> sk->sk_prot->recvmsg() // tcp_recvmsg
											
								
								
								
tcp_prequeue  wake_up_interruptible		
tcp_sendmsg sk_stream_wait_connect	


Source Port		:	th->source = inet->sport;
Destination Port:	th->dest   = inet->dport;
Seqence Number	:	th->seq	   = htonl(tcb->seq);
Ack Number		:	th->ack_seq = htonl(tp->rcv_nxt);
Data Offset		:	((tcp_header_size >> 2) << 12)
Flags			:	tcb->flags
Window			:	th->window = htons(min(tp->rcv_wnd, 65535U)) ���� th->window = htons(tcp_select_window(sk)); 
					<= ע�����������window_scale �����ʾ����window scale���ֵ
					<= newwinֵȷ��:
						1. tcp_receive_window(rcv_wnd,rcv_nxt,rcv_wup)
						2. __tcp_select_window(tp->window_clamp,sk->sk_rcvbuf,sk->sk_rmem_alloc,tp->rcv_ssthresh)
						3. ����tp->rcv_ssthresh�ĸ�ֵ
						����ˣ�tcp_select_initial_window(&req->rcv_wnd)//�յ�SYN�� tcp_make_synack <- __tcp_v4_send_synack <- tcp_v4_conn_request
								tp->rcv_ssthresh = req->rcv_wnd; 
								����window_clampҲ�����
Checksum		:	icsk->icsk_af_ops->send_check(sk, skb->len, skb);
Urgent Pointer	:
Options			:	tcp_options_write
Padding			:	tcp_options_write


tcb->seq: �Ǵ�����skb��sequence Number
tp->write_seq: tcb_seq+1
tp->snd_up: �Ǻ�OutBand Data�� snd_up �������һ��tcp ���ݱ���seqence Number����
					