#include <stdlib.h>
#include <stdio.h>

void handler() {
    char *raw = getenv("PORT");
    int port = atoi(raw);
    char buf[16];
    snprintf(buf, sizeof(buf), "%d", port);
}
