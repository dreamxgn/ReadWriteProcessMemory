#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include<unistd.h>
 
int main()
{
    int *ptr=(int*)malloc(sizeof(unsigned int));
    *ptr=1992;
    while(1)
    {
        printf("pid %ld vaddr %ld value %d\n",getpid(),ptr,*ptr);
        sleep(2);
    }
    return 0;
}
