#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle(int argc, char **argv)
{
    char buf[64];
    if (argc > 1) {
        snprintf(buf, sizeof(buf), "%s", argv[1]);
    }
    fgets(buf, sizeof(buf), stdin);
    printf("%s", argv[1]);
    FILE *f = fopen("/data/static.txt", "r");
    SHA256_Init(&ctx);
    (void)f;
}
