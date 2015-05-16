#include <stdio.h>
#include "jhash.h"

int main()
{
	unsigned int result = 0;
	//net=809d6c10 hashinfo=809da5c0 saddr=0xc0a8010e sport=0x112c daddr=0xc0a80101 hnum=0x15 dif=10
	result = jhash_3words(0xc0a80101, 0xc0a8010e, 0x15 << 16 | 0x112c, 0x8ff8d0c2);
	printf("result = 0x%x\n", result);
	return 0;
}


