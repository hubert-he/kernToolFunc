accept
	=> inet_csk_wait_for_connect 
		=> DEFINE_WAIT(wait);
			=> .func = autoremove_wake_function
		=> while(1)
				prepare_to_wait_exclusive(sk->sk_sleep, &wait,TASK_INTERRUPTIBLE);
					=> wait->flags |= WQ_FLAG_EXCLUSIVE// ��ֵ����
					=> ��wait��sk_sleep�Ϲ�
					=> set_current_state(TASK_INTERRUPTIBLE)
				release_sock(sk);
				timeo = schedule_timeout(timeo); // ��û�����ӣ�����
					=> schedule();
						=> __schedule()
		=> finish_wait(sk->sk_sleep, &wait);
			
------------------------
��֮��Ӧ����tcp_child_process �յ���3��ACK���ĺ󣬿��Ի��ѽ���
tcp_child_process	
	if (!sock_owned_by_user(child))
		sock_def_readable
	else
		sk_add_backlog

sock_def_readable
	=> wake_up_interruptible_sync_poll
	-> __wake_up_sync_key(sk->sk_sleep, TASK_INTERRUPTIBLE, 1, (void *) (m))
		=> __wake_up_common(sk->sk_sleep, mode, nr_exclusive, sync, key=m);
			=> ѭ������curr->func������inet_csk_wait_for_connect definewait�����autoremove_wake_function
	=> sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	
	
autoremove_wake_function
	=> default_wake_function(wait, mode, sync, key) // wait Ϊwait_queue_t����
		=> try_to_wake_up(curr->private, mode, sync) // ��ʱ��Ϊcurrent��task_struct
			=> 
	
	
 #if xxx_comment
 #define DEFINE_WAIT_FUNC(name, function)				\
	wait_queue_t name = {						\
		.private	= current,				\
		.func		= function,				\
		.task_list	= LIST_HEAD_INIT((name).task_list),	\
	}
#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)

wait_queue_t wait = 
{						
	.private	= current,				
	.func		= autoremove_wake_function, 			
	.task_list	= { &(wait.task_list), &(wait.task_list)}, 
};
#endif	