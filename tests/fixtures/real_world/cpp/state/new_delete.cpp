#include <cstring>

void leak() {
    char *buf = new char[1024];
    strcpy(buf, "hello");
}

void clean() {
    char *buf = new char[1024];
    strcpy(buf, "hello");
    delete[] buf;
}

void double_delete() {
    char *buf = new char[1024];
    delete[] buf;
    delete[] buf;
}
