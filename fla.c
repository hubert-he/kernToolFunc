struct x {
   int a;
   char *b;
};

struct y {
   int a;
   char b[]; // C99���淨�ǣ�char contents[]; û��ָ�����鳤��
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