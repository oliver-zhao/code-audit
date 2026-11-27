/* Seeds for the Opengrep C rules: environment and argv data reaching a shell
 * command through a formatted buffer, and argv used as a format string. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    char cmd[256];
    const char *editor = getenv("EDITOR");
    snprintf(cmd, sizeof(cmd), "%s %s", editor, argv[1]);
    if (argc > 2) {
        fprintf(stderr, argv[2]);
    }
    return system(cmd);
}
