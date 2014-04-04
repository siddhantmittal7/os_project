#include<stdio.h>
int main()
{
	int i=100000;
	int j=100000;
	//syscall(401,20000);
	while(i>0){
		i--;
		while(j>0) j--;
			j=10000;
		printf("AIOI%d\n",i);
	}
	printf("I started");
	return 0;
}
