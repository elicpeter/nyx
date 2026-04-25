#include <stdlib.h>
#include <curl/curl.h>

void fetch_url() {
    char *url = getenv("TARGET_URL");
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}
