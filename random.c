/*
 * This function is the exported kernel interface.  It returns some
 * number of good random numbers, suitable for seeding TCP sequence
 * numbers, etc.
 */
void get_random_bytes(void *buf, int nbytes)
{
	extract_entropy(&nonblocking_pool, buf, nbytes, 0, 0);
}