/* Seeds for the C command, file, privilege and randomness rules. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

int run_hook(char **argv, const char *script)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "sh %s", script);
    system(cmd);                                         /* cpp-system-api */
    FILE *pipe = popen(getenv("HOOK_CMD"), "r");         /* cpp-system */
    execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);     /* cpp-exec-shell-c */
    FILE *in = fopen(argv[1], "r");                      /* cpp-path-traversal */
    FILE *cfg = fopen(script, "r");                      /* cpp-fopen-api */
    (void)pipe;
    (void)in;
    (void)cfg;
    return 0;
}

int write_report(const char *path, const char *text)
{
    char name[L_tmpnam];
    tmpnam(name);                                        /* cpp-insecure-tempfile */
    if (access(path, W_OK) == 0) {                       /* cpp-access-toctou */
        int fd = open(path, O_WRONLY | O_TRUNC);
        write(fd, text, strlen(text));
        close(fd);
    }
    return 0;
}

void drop_privileges(uid_t uid, gid_t gid, const char *jail)
{
    umask(0);                                            /* cpp-umask-zero */
    chroot(jail);                                        /* cpp-chroot-without-chdir */
    setgid(gid);                                         /* cpp-setuid-unchecked */
    setuid(uid);                                         /* cpp-setuid-unchecked */
}

void make_session(unsigned char *session_key, int n)
{
    char password[64];
    srand(time(NULL));                                   /* cpp-srand-time */
    for (int i = 0; i < n; i++) {
        session_key[i] = rand() % 256;                   /* cpp-rand-security-value */
    }
    memset(password, 0, sizeof(password));              /* cpp-memset-secret */
}
