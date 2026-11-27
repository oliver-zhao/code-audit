#include <stdio.h>
#include <stdlib.h>

void run(const char *command, const char *path)
{
    system(command);
    FILE *f = fopen(path, "r");
    (void)f;
}
