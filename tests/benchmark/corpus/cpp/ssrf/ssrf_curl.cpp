#include <cstdlib>
#include <curl/curl.h>

int main() {
    char *url = getenv("TARGET_URL");
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return 0;
}
