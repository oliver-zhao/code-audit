/* Seeds for the Opengrep C rules: environment and argv data reaching a shell
 * command through a formatted buffer, and argv used as a format string. */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char cmd[256];
    const char *editor = getenv("EDITOR");
    const char *fmt = argc > 3 ? argv[3] : "%s";
    snprintf(cmd, sizeof(cmd), "%s %s", editor, argv[1]);
    if (argc > 2) {
        fprintf(stderr, argv[2]);
        syslog(LOG_INFO, fmt, editor);
    }
    if (argc > 4) {
        execl("/bin/sh", "sh", "-c", argv[4], (char *)NULL);
    }
    return system(cmd);
}
