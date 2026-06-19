#include <stdlib.h>

void handler() {
    char *cmd = getenv("CMD");
    system(cmd);
}
