#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Clean open/close — no findings expected */
void clean_usage(void) {
    FILE *f = fopen("data.txt", "r");
    char buf[256];
    fread(buf, 1, 256, f);
    fclose(f);
}

/* Resource leak — fopen without fclose */
void leaky_function(void) {
    FILE *f = fopen("log.txt", "w");
    fprintf(f, "hello");
}

/* Use after close */
void use_after_close(void) {
    FILE *f = fopen("tmp.txt", "r");
    fclose(f);
    char buf[64];
    fread(buf, 1, 64, f);
}

/* Branch leak — closed on one path only */
void branch_leak(int cond) {
    FILE *f = fopen("x.txt", "r");
    if (cond) {
        fclose(f);
    }
}

/* Multiple handles — both properly closed */
void multi_handle(void) {
    FILE *a = fopen("a.txt", "r");
    FILE *b = fopen("b.txt", "w");
    fclose(a);
    fclose(b);
}

/* Double close */
void double_close(void) {
    FILE *f = fopen("d.txt", "r");
    fclose(f);
    fclose(f);
}

/* Malloc/free — clean */
void malloc_clean(void) {
    char *p = malloc(1024);
    memset(p, 0, 1024);
    free(p);
}

/* Malloc leak — never freed */
void malloc_leak(void) {
    char *p = malloc(512);
    memset(p, 0, 512);
}
