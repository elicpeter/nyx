#include <stdio.h>
#include <stdlib.h>

void handle_command(int cmd, char *arg) {
    switch (cmd) {
        case 1:
            system(arg);
            break;
        case 2:
            printf("%s\n", arg);
            break;
        case 3:
            system(arg);  // no break - falls through
        case 4:
            printf("Done\n");
            break;
        default:
            break;
    }
}
