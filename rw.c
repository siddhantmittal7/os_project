#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
	int i;
	char* arr;
	arr =  malloc(500*sizeof(char));
	for(i=0; i <499; i++)
		arr[i] = '2';
	arr[i] = '\0';
	srand(time(NULL));
	int k = 2;
	printf("\nBlock no: %d\n",k);
	syscall(402,'w',500,  arr, k ,500);
	syscall(402,'r',500,  arr, k ,500);
	
	return 0;
}

