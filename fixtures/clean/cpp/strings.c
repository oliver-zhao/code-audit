/* Safe counterparts of fixtures/vulnerable/cpp/strings.c. */
#include <err.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define _(text) gettext(text)
#define USAGE "usage: tool [-v] file\n"

struct packet {
    char name[32];
    char data[256];
};

void copy_inputs(int argc, char **argv, const char *peer)
{
    char host[64];
    char line[128];
    char path[256];
    const char *tmp = getenv("TMPDIR");

    snprintf(path, sizeof(path), "%s/.config/%s", tmp ? tmp : "/tmp", argc > 1 ? argv[1] : "app");
    snprintf(host, sizeof(host), "%s", peer);
    snprintf(line, sizeof(line), "user=%.20s", peer);
    if (scanf("%127s", line) != 1) {
        return;
    }
    sscanf(peer, "%d %127[^\n]", &argc, line);
}

void log_message(const char *msg, char **argv)
{
    char out[128];
    printf("%s", msg);
    fprintf(stderr, "%s\n", argv[2]);
    syslog(LOG_ERR, "%s", msg);
    snprintf(out, sizeof(out), "%s", msg);
    warnx("%s", msg);
    printf(_("Configuration loaded\n"));
    fprintf(stderr, USAGE);
    printf(gettext("Done\n"));
}

void copy_packet(struct packet *pkt, const char *src)
{
    char small[16];
    size_t used = strlen(pkt->name);
    memcpy(small, pkt->data, sizeof(small));
    strncpy(small, src, sizeof(small) - 1);
    small[sizeof(small) - 1] = '\0';
    strncat(pkt->name, src, sizeof(pkt->name) - used - 1);
}

char *grow(char *buf, size_t count, size_t width, size_t len)
{
    char scratch[64];
    char *table = calloc(count, width);
    char *bigger = realloc(buf, len);
    if (bigger == NULL) {
        free(table);
        return buf;
    }
    (void)scratch;
    free(table);
    return bigger;
}
