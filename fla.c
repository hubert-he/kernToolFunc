struct x {
   int a;
   char *b;
};

struct y {
   int a;
   char b[]; // C99的玩法是：char contents[]; 没有指定数组长度
};
 
int main(){
    int len=10;
    struct x *xx = (struct line *)malloc (sizeof (struct x));
    xx->b = (char*) malloc( sizeof(char) * len);
    xx->a = len;
    memset(xx->b, 'a', len);
	
	struct y y;
	y.b = (char*) malloc( sizeof(char)*10 );
	y.a = 10;
	memset(y.b, 'y', len);
    return 0;
}