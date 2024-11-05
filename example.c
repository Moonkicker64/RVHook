#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "rvhook.h"



int (*ptest)(int,int) = NULL;

int test(int a, int b)
{
    printf("test()\n");
    return a+b;
}

int hooktest(int a,int b)
{
    printf("hooked test()\n");
    int r = ptest(a+1,b);
    return r;
}


int main()
{
    int r = test(2,3);
    printf("test return value : %d\n",r);

    RVHook((uintptr_t)test,(uintptr_t)hooktest,(void**)&ptest);

    r = test(2,3);
    printf("test return value : %d\n",r);

    return 0;
}