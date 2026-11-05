#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char name[16];
    char command[64];
    gets(name);
    strcpy(name, argv[1]);
    sprintf(command, "echo %s", argv[1]);
    scanf("%s", name);
    printf(argv[1]);
    fprintf(stderr, name);
    system(command);
    char *path = tmpnam(NULL);
    return 0;
}
