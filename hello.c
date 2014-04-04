#include<stdio.h>
int main(){
	char s[20000];
	s[0] = 'a';
	s[1] = 'b';
	while(1)
	{
		//syscall(402,'w',2,s,300,2);
		s[1] = 'd';
		printf("out\n");
	}
	return 0;
}
