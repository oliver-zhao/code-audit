#include <stdio.h>
#include <stdlib.h>

void run(void)
{
    system("ls -l");
    FILE *f = fopen("/data/static.txt", "r");
    (void)f;
}
