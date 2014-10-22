#include <stdio.h>
struct qstr {
	unsigned int hash;
	unsigned int len;
	const unsigned char *name;
};
/* partial hash update function. Assume roughly 4 bits per character */
static inline unsigned long
partial_name_hash(unsigned long c, unsigned long prevhash)
{
	return (prevhash + (c << 4) + (c >> 4)) * 11;
}

/*
 * Finally: cut down the number of bits to a int value (and try to avoid
 * losing bits)
 */
static inline unsigned long end_name_hash(unsigned long hash)
{
	return (unsigned int) hash;
}
#define init_name_hash()		0
int main()
{
	struct qstr this;
	char *name = "what the hell";
	this.name = name;
	unsigned long hash;
	unsigned int c = *(const unsigned char *)name;
	hash = init_name_hash();
	do 
	{
		name++;
		printf("%x:%u  %x:%u\n", hash,hash, c, c);
		hash = partial_name_hash(c, hash);
		c = *(const unsigned char *)name;
	} while (c && (c != '/'));
	this.len = name - (const char *) this.name;
	this.hash = end_name_hash(hash);
	printf("%x: %u: %s\n", this.hash, this.len, this.name);
	return 0;
}


















