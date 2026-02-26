#include <cstring>
#include <cstdio>

struct Header {
    int type;
    int length;
};

void parse_packet(const char *data) {
    Header *hdr = reinterpret_cast<Header*>(const_cast<char*>(data));
    printf("Type: %d, Length: %d\n", hdr->type, hdr->length);
}
