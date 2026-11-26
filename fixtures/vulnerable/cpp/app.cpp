#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle(int argc, char **argv)
{
    char buf[64];
    strcpy(buf, argv[1]);
    gets(buf);
    sprintf(buf, "%s", argv[1]);
    system(argv[1]);
    printf(argv[1]);
    FILE *f = fopen(argv[1], "r");
    MD5_Init(&ctx);
    (void)f;
    (void)argc;
}
