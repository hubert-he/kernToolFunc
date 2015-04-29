int sysctl_tcp_low_latency = 0; // 0: 表示高吞吐量, tcp使用prequeue队列 || 1:表示低延迟，tcp不绕过prequeue队列
int sysctl_tcp_syncookies = 0; // 
int sysctl_max_syn_backlog = 256;//Maximum number of SYN_RECV sockets in queue per LISTEN socket. 同时somaxconn协同
int sysctl_tcp_fack = 1;

