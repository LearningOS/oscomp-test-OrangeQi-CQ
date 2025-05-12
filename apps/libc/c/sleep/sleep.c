#include <stdio.h>
#include <unistd.h>
int main()
{
    printf("Sleeping for 5 seconds...\n");
    sleep(1);
    printf("Done!\n");
    return 0;
}