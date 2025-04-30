#include <stdio.h>
#include <unistd.h>
int main()
{
    printf("Sleeping for 1 seconds...\n");
    sleep(1);
    printf("Done!\n");
    return 0;
}