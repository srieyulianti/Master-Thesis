#define CURL_STATICLIB
#include <stdio.h>
#include <curl/curl.h>
/*#include <curl/types.h>
#include <curl/easy.h>*/
#include <string.h>
#include <stdlib.h>

#define false 0

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written;
    written = fwrite(ptr, size, nmemb, stream);
    return written;
}

int main(void) {
    CURL *curl;
    FILE *fp;
    CURLcode res;

    const char url[] = "https://storage.googleapis.com/download.tensorflow.org/models/mobilenet_v1_2018_02_22/mobilenet_v1_1.0_224.tgz";
    const char outfilename[FILENAME_MAX] = "./model.tgz";

    curl_version_info_data * vinfo = curl_version_info(CURLVERSION_NOW);

    if(vinfo->features & CURL_VERSION_SSL){
        printf("CURL: SSL enabled\n");
    }else{
        printf("CURL: SSL not enabled\n");
    }

    curl = curl_easy_init();
    if (curl) {
        fp = fopen(outfilename,"wb");

        /* Setup the https:// verification options. Note we   */
        /* do this on all requests as there may be a redirect */
        /* from http to https and we still want to verify     */
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CAINFO, "./ca-certificates.crt");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        int i=fclose(fp);
        if( i==0)
	system("mkdir models");
	system("tar -xf model.tgz -C ./models");
        //system("mv -f model.tgz ./models && cd models");
	//system("cd models");
	//system("tar -xvf ./models/model.tgz");
    }
    return 0;
}
