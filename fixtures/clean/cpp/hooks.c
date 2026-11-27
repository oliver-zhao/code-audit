/* Safe counterpart of fixtures/vulnerable/cpp/hooks.c. */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char cmd[64];
    const char *editor = getenv("EDITOR");
    if (argc > 2) {
        fprintf(stderr, "%s\n", argv[2]);
        syslog(LOG_INFO, "editor: %s", editor ? editor : "none");
    }
    if (argc > 3) {
        /* A number parsed from argv cannot carry shell syntax. */
        int seconds = atoi(argv[3]);
        snprintf(cmd, sizeof(cmd), "sleep %d", seconds);
        return system(cmd);
    }
    if (editor != NULL && argc > 1) {
        execlp(editor, editor, argv[1], (char *)NULL);
    }
    return 1;
}
