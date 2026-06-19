#include <stdlib.h>
#include <string.h>

void handler() {
    char *name = getenv("NAME");
    char buf[16];
    strcpy(buf, name);
}
