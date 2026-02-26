#include <stdlib.h>
#include <string.h>

char *duplicate_string(const char *input) {
    char *buf = malloc(strlen(input) + 1);
    if (buf == NULL) return NULL;
    strcpy(buf, input);
    return buf;
}

void process_data(const char *input) {
    char *copy = malloc(strlen(input) + 1);
    if (copy == NULL) return;
    strcpy(copy, input);

    if (strlen(copy) > 100) {
        return;  // memory leak!
    }

    free(copy);
}
