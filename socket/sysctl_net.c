int sysctl_tcp_low_latency = 0; // 0: ��ʾ��������, tcpʹ��prequeue���� || 1:��ʾ���ӳ٣�tcp���ƹ�prequeue����
int sysctl_tcp_syncookies = 0; // 
int sysctl_max_syn_backlog = 256;//Maximum number of SYN_RECV sockets in queue per LISTEN socket. ͬʱsomaxconnЭͬ
int sysctl_tcp_fack = 1;
int sysctl_tcp_tso_win_divisor = 3; // tcp_tso_should_defer
int sysctl_tcp_reordering = 3; //tcp_tso_should_defer
int sysctl_tcp_slow_start_after_idle = 1; // ���г���1��rto�����½���������
