#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char name[16];
    snprintf(name, sizeof(name), "%s", argv[1]);
    fgets(name, sizeof(name), stdin);
    printf("%s\n", name);
    fprintf(stderr, "failed\n");
    system("clear");
    return 0;
}
