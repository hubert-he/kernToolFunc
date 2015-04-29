__inet_lookup
{
	__inet_lookup_established
	__inet_lookup_listener
}


__inet_lookup_established
{
	unsigned int hash = inet_ehashfn(net, daddr, hnum, saddr, sport);
    unsigned int slot = hash & (hashinfo->ehash_size - 1);
    struct inet_ehash_bucket *head = &hashinfo->ehash[slot];
	
	sk_nulls_for_each_rcu(sk, node, &head->chain) <== chain
	sk_nulls_for_each_rcu(sk, node, &head->twchain) <== twchain
}
__inet_lookup_listener
{
	unsigned int hash = inet_lhashfn(net, hnum);
    struct inet_listen_hashbucket *ilb = &hashinfo->listening_hash[hash];
}