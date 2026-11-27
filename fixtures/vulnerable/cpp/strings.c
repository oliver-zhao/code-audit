/* Seeds for the C string, copy and format rules. Each marked line is a seed. */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

struct packet {
    char name[32];
    char data[256];
};

void copy_inputs(int argc, char **argv, const char *peer)
{
    char host[64];
    char line[128];
    char path[256];
    char *home = getenv("HOME");

    strcat(path, getenv("TMPDIR"));                      /* cpp-strcpy */
    strcpy(host, peer);                                  /* cpp-strcpy-api */
    lstrcpyA(line, peer);                                /* cpp-strcpy-api */
    sprintf(path, "%s/.config/%s", home, argv[1]);       /* cpp-sprintf */
    sprintf(line, "user=%-20s", peer);                   /* cpp-sprintf-api */
    if (scanf("%s", line) != 1) {                        /* cpp-scanf-unbounded-string */
        return;
    }
    sscanf(peer, "%d %[^\n]", &argc, line);              /* cpp-scanf-unbounded-string */
    (void)argc;
}

void log_message(const char *msg, char **argv)
{
    char out[128];
    printf(msg);                                         /* cpp-format-string */
    fprintf(stderr, argv[2]);                            /* cpp-format-string */
    syslog(LOG_ERR, msg);                                /* cpp-format-string */
    snprintf(out, sizeof(out), msg);                     /* cpp-format-string */
    warnx(msg);                                          /* cpp-format-string-err */
    err(1, msg);                                         /* cpp-format-string-err */
}

void copy_packet(struct packet *pkt, const char *src, char *dst)
{
    char small[16];
    memcpy(small, pkt->data, sizeof(pkt->data));         /* cpp-copy-size-from-source */
    memcpy(dst, src, strlen(src));                       /* cpp-copy-size-from-source */
    strncpy(small, src, strlen(src));                    /* cpp-strncpy-source-length */
    strncat(pkt->name, src, sizeof(pkt->name));          /* cpp-strncat-full-size */
    strncpy(pkt->name, src, sizeof(pkt->name));          /* cpp-strncpy-no-nul */
}

char *grow(char *buf, size_t count, size_t width, size_t len)
{
    char *scratch = alloca(len);                         /* cpp-alloca-dynamic */
    char *table = malloc(count * width);                 /* cpp-malloc-multiply */
    buf = realloc(buf, len * 2);                         /* cpp-realloc-self-assign */
    (void)scratch;
    (void)table;
    return buf;
}

void log_windows(const char *msg, char *out, size_t n)
{
    printf_s(msg);                                       /* cpp-format-string */
    _snprintf_s(out, n, _TRUNCATE, msg);                 /* cpp-format-string */
    fprintf(stderr, (const char *)msg + 1);              /* cpp-format-string */
}
