#define FLAG_IMPLEMENTATION
#include "flag.h"

#define STB_DS_IMPLEMENTATION
#include "../thirdparty/stb_ds.h"

#define CJSON_NO_STB_DS
#include "../C-JSON/parser.h"



#define NOB_IMPLEMENTATION
#include "../thirdparty/nob.h"

#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <time.h>
#include <assert.h>

#define DOWNLOAD_STATE_OK             0
#define DOWNLOAD_STATE_RATELIMITED    1
#define DOWNLOAD_STATE_ALREADY_EXISTS 2
#define DOWNLOAD_STATE_FS_ERROR       3

#ifdef _WIN32
    #include <windows.h>
    #define sleep_seconds(x) Sleep((x) * 1000)
#else
    #include <unistd.h>
    #define sleep_seconds(x) sleep(x)
#endif


#define CERTIFICATE_PATH "/etc/ssl/certs/ca-certificates.crt"

#define FALLBACK_LANGUAGE "ja-ro"
#define FALLBACK_LANGUAGE_SIZE 5

#define TYPE_CHECK_FIELD_GET(obj, key, expected_type)                    \
do {                                                                     \
    key = shget((obj)->object, #key);                                    \
    if (!(key) || (key)->type != (expected_type)) {                      \
        fprintf(stderr, "[Error] Invalid or missing field: %s\n", #key); \
        goto defer;                                                      \
    }                                                                    \
} while(0)


#include "mangadex_api.h"


void usage(FILE *stream){
    fprintf(stream, "Usage: ./example [OPTIONS] [--] [ARGS]\n");
    fprintf(stream, "OPTIONS:\n");
    flag_print_options(stream);
}


static bool is_hex(char c) {
    return isxdigit((unsigned char)c);
}


bool is_valid_uuid_v4(const char *uuid) {
    if (!uuid) return false;

    if (strlen(uuid) != 36) return false;

    if (uuid[8]  != '-' ||
        uuid[13] != '-' ||
        uuid[18] != '-' ||
        uuid[23] != '-') {
        return false;
    }

    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23)
            continue;

        if (!is_hex(uuid[i]))
            return false;
    }

    if (uuid[14] != '4')
        return false;

    char v = tolower((unsigned char)uuid[19]);
    if (!(v == '8' || v == '9' || v == 'a' || v == 'b'))
        return false;

    return true;
}


void str_replace(char* str, char from, char to){
    int i = 0;
    while(str[i]){
        if(str[i] == from){
            str[i] = to;
        }
        i++;
    }
}

void str_lower(char* str){
    int i = 0;
    while(str[i]){
        str[i] = tolower(str[i]);
        i++;
    }
}


void draw_progress(int N, int total) {
    int width = 30;

    int percent = (total > 0) ? (N * 100) / total : 0;
    if (percent > 100) percent = 100;

    int filled = (total > 0) ? (N * width) / total : 0;
    if (filled > width) filled = width;

    printf("Progress: [");
    for (int i = 0; i < width; i++)
        putchar(i < filled ? '#' : ' ');

    printf("] %d%% (%d/%d)\n", percent, N, total);
}

int main(int argc, char** argv){
    nob_minimal_log_level = NOB_WARNING;
    char** uuid = flag_str("uuid", NULL, "uuid of manga you want to download");
    char** library_path = flag_str("lib_path", NULL, "Path to the library directory (manga will be downloaded to directory inside the path)");
    char** language = flag_str("language", NULL, "Prefered language (en, ja)");

    if (!flag_parse(argc, argv)) {
        usage(stderr);
        flag_print_error(stderr);
        exit(1);
    }
    if(*uuid == NULL || *library_path == NULL || *language == NULL){
        usage(stderr);
        exit(1);
    }
    if(!is_valid_uuid_v4(*uuid)){
        fprintf(stderr, "[Error] Provided uuid is not a valid uuid4\n");
        exit(1);
    }
    if(nob_file_exists(*library_path) != 1){
        fprintf(stderr, "[Error] Library path is not a valid path or it does not exist\n");
        exit(1);
    }
    if(nob_get_file_type(*library_path) != NOB_FILE_DIRECTORY){
        fprintf(stderr, "[Error] Library path is not a directory\n");
        exit(1);
    }
    JsonValue* aggregate = get_manga_aggregate(*uuid, *language);
    if(!aggregate){
        fprintf(stderr, "[Error] Manga aggregate could not be loaded\n");
        exit(1);
    }
    JsonValue* info = get_manga_info(*uuid);
    if(!info){
        fprintf(stderr, "[Error] Manga info could not be loaded\n");
        exit(1);
    }
    JsonValue* data = NULL;
    JsonValue* attributes = NULL;
    JsonValue* title = NULL;
    JsonValue* altTitles = NULL;

    char* pref_title    = NULL;
    char* fallback_title = NULL; 

    TYPE_CHECK_FIELD_GET(info, data, JSON_OBJECT);
    TYPE_CHECK_FIELD_GET(data, attributes, JSON_OBJECT);
    TYPE_CHECK_FIELD_GET(attributes, title, JSON_OBJECT);

    for(int i = 0; i < shlen(title->object); i++){
        JsonPair pair = title->object[i];
        if(strncmp(pair.key, *language, strlen(*language)) == 0){
            pref_title = pair.value->string;
        }
        else if(strncmp(pair.key, FALLBACK_LANGUAGE, FALLBACK_LANGUAGE_SIZE) == 0){
            fallback_title = pair.value->string;
        }
    }
    if(pref_title == NULL){
        TYPE_CHECK_FIELD_GET(attributes, altTitles, JSON_ARRAY);
        for(int i = 0; i < arrlen(altTitles->array); i++){
            for(int j = 0; j < shlen(altTitles->array[i]->object); j++){
                JsonPair pair = altTitles->array[i]->object[j];
                if(strncmp(pair.key, *language, strlen(*language)) == 0){
                    pref_title = pair.value->string;
                }
            }
        }
    }
    char* directory_name = NULL;
    if(pref_title){
        directory_name = pref_title;
    }else if(!pref_title && fallback_title){
        directory_name = fallback_title;
    }else if(!pref_title && !fallback_title){
        fprintf(stderr, "[Warning] Could not find title in prefered language or fallback (ja-ro) using uuid as name\n");
        directory_name = *uuid;
    }

    if(directory_name == pref_title || directory_name == fallback_title){
        str_replace(directory_name, ' ', '_');
        str_lower(directory_name);
    }
    char manga_path[8192] = {0};
    snprintf(manga_path, sizeof(manga_path), "%s/%s", *library_path, directory_name);
    if(!nob_mkdir_if_not_exists(manga_path)){
        fprintf(stderr, "[Error] Could not create directory for the manga in library path!\n");
        exit(1);
    }
    JsonValue* volumes = NULL;
    JsonValue* chapters = NULL;
    JsonValue* id = NULL;


    size_t total_chapters = 0;
    size_t downloaded     = 0;
    
    /* First pass: count chapters */
    TYPE_CHECK_FIELD_GET(aggregate, volumes, JSON_OBJECT);
    for (int volume_i = 0; volume_i < shlen(volumes->object); volume_i++) {
        JsonPair volume_pair = volumes->object[volume_i];
        chapters = NULL;
        TYPE_CHECK_FIELD_GET(volume_pair.value, chapters, JSON_OBJECT);
        for (int chapter_i = 0; chapter_i < shlen(chapters->object); chapter_i++) {
            total_chapters++;
        }
    }
    

    volumes = NULL;
    TYPE_CHECK_FIELD_GET(aggregate, volumes, JSON_OBJECT);
    for (int volume_i = 0; volume_i < shlen(volumes->object); volume_i++) {
        JsonPair volume_pair = volumes->object[volume_i];
        chapters = NULL;
        TYPE_CHECK_FIELD_GET(volume_pair.value, chapters, JSON_OBJECT);
    
        for (int chapter_i = 0; chapter_i < shlen(chapters->object); chapter_i++) {
            JsonPair chapter_pair = chapters->object[chapter_i];
            id = NULL;
            TYPE_CHECK_FIELD_GET(chapter_pair.value, id, JSON_STRING);
    
            uint8_t state = 0;
            download_chapter(id->string, manga_path,
                             volume_pair.key, chapter_pair.key, &state);
    
            if (state == DOWNLOAD_STATE_RATELIMITED) {
                state = 0;
                download_chapter(id->string, manga_path,
                                 volume_pair.key, chapter_pair.key, &state);
                if (state != DOWNLOAD_STATE_OK) {
                    fprintf(stderr, "[Warning] Could not download Vol. %s Ch. %s after ratelimit\n",
                              volume_pair.key, chapter_pair.key);
                    continue;
                }
            } else if (state == DOWNLOAD_STATE_ALREADY_EXISTS) {
                fprintf(stderr, "[Info] Vol. %s Ch. %s already downloaded\n",
                          volume_pair.key, chapter_pair.key);
                downloaded++;
                continue;
            } else if (state == DOWNLOAD_STATE_FS_ERROR) {
                fprintf(stderr, "[Error] Could not create directories for Vol. %s Ch. %s\n",
                          volume_pair.key, chapter_pair.key);
                continue;
            } else if (state != DOWNLOAD_STATE_OK) {
                assert(0 && "Impossible state");
            }
            downloaded++;
            draw_progress(downloaded, total_chapters);
        }
    }
    
    fprintf(stderr, "\n");

defer:
    json_free(aggregate);
    json_free(info);

    return 0;
}