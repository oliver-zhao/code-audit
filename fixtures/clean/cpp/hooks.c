/* Safe counterpart of fixtures/vulnerable/cpp/hooks.c. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *editor = getenv("EDITOR");
    if (argc > 2) {
        fprintf(stderr, "%s\n", argv[2]);
    }
    if (editor != NULL && argc > 1) {
        execlp(editor, editor, argv[1], (char *)NULL);
    }
    return 1;
}
