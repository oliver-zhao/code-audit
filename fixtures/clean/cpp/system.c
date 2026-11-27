/* Safe counterparts of fixtures/vulnerable/cpp/system.c. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

int run_hook(const char *script)
{
    char *const args[] = {"/usr/bin/env", "sh", (char *)script, NULL};
    pid_t pid = fork();
    if (pid == 0) {
        execv("/usr/bin/env", args);
        _exit(127);
    }
    FILE *cfg = fopen("/etc/app/hooks.conf", "r");
    (void)cfg;
    return 0;
}

int write_report(const char *text)
{
    char name[] = "/tmp/report-XXXXXX";
    int fd = mkstemp(name);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) {
        return -1;
    }
    write(fd, text, strlen(text));
    close(fd);
    return 0;
}

void drop_privileges(uid_t uid, gid_t gid, const char *jail)
{
    mode_t previous = umask(0);
    umask(previous);
    umask(077);
    if (chroot(jail) != 0 || chdir("/") != 0) {
        abort();
    }
    if (setgid(gid) != 0 || setuid(uid) != 0) {
        abort();
    }
}

void make_session(unsigned char *session_key, size_t n)
{
    char password[64];
    if (getrandom(session_key, n, 0) != (ssize_t)n) {
        abort();
    }
    explicit_bzero(password, sizeof(password));
}
