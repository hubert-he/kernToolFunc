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
											=> tcp_create_openreq_child // �������µ�sock����ֵ
											=> __inet_hash_nolisten // hashinfo->ehash,��ӵ�established
											=> __inet_inherit_port // icsk_bind_hash & hashinfo->bhash����
										=> inet_csk_reqsk_queue_unlink // ��icsk_accept_queue.listen_optժ��
										=> inet_csk_reqsk_queue_add // ��ӵ�icsk_accept_queue.rksq_accept_head��ȥ
									=> tcp_child_process
										=> tcp_rcv_state_process
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
								
								
								
								
								
tcp_prequeue  wake_up_interruptible								