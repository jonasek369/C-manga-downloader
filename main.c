#include <stdio.h>
#include <curl/curl.h>
#include <windows.h>
#include <stdatomic.h>

#define NOB_IMPLEMENTATION
#include "nob.h"


#include "json_parser.h"


#define CERTIFICATE_PATH "curl-ca-bundle.crt"
#define UUID4_SIZE 36
#define CHAPTER_DOWNLOAD_URL_SIZE 40

atomic_bool paused = false;
atomic_bool stopped = false;
atomic_bool downloading = false;
atomic_bool ratelimited = false;

atomic_int job_chapters_downloaded = 0;

atomic_int job_chapters = 0;


CRITICAL_SECTION cs;
char shared_cwo[37];


const uint32_t MS_IN_SECONDS = 1000;

void init_cwo() {
    InitializeCriticalSection(&cs);
}

void set_cwo(const char *s) {
    EnterCriticalSection(&cs);
    strncpy(shared_cwo, s, 36);
    shared_cwo[36] = '\0';
    LeaveCriticalSection(&cs);
}

void get_cwo(char *buffer, size_t size) {
    EnterCriticalSection(&cs);
    strncpy(buffer, shared_cwo, size - 1);
    buffer[size - 1] = '\0';
    LeaveCriticalSection(&cs);
}

void cleanup_cwo() {
    DeleteCriticalSection(&cs);
}


static void sb_append(char **buf, const char *fmt, ...) {
    char temp[1024];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(temp, sizeof(temp), fmt, args);
    va_end(args);

    if (n < 0) return;

    if ((size_t)n >= sizeof(temp)) {
        char *heapbuf = malloc(n + 1);
        va_start(args, fmt);
        vsnprintf(heapbuf, n + 1, fmt, args);
        va_end(args);
        for (int i = 0; i < n; i++)
            arrpush(*buf, heapbuf[i]);
        free(heapbuf);
    } else {
        for (int i = 0; i < n; i++)
            arrpush(*buf, temp[i]);
    }
}

// Single-line JSON serialization
void json_print_compact(JsonValue *json, char **out) {
    switch (json->type) {
        case JSON_OBJECT: {
            sb_append(out, "{");
            JsonPair *pairs = json->object;
            size_t first = 1;
            for (size_t slot = 0; slot < hmlenu(pairs); slot++) {
                if (pairs[slot].key == NULL) continue;
                if (!first) sb_append(out, ",");
                first = 0;
                sb_append(out, "\"%s\":", pairs[slot].key);
                json_print_compact(pairs[slot].value, out);
            }
            sb_append(out, "}");
            break;
        }

        case JSON_ARRAY: {
            sb_append(out, "[");
            JsonValue **values = json->array;
            size_t count = arrlen(values);
            for (size_t i = 0; i < count; i++) {
                if (i > 0) sb_append(out, ",");
                json_print_compact(values[i], out);
            }
            sb_append(out, "]");
            break;
        }

        case JSON_STRING:
            sb_append(out, "\"%s\"", json->string);
            break;
        case JSON_NUMBER:
            sb_append(out, "%g", json->number);
            break;
        case JSON_BOOL:
            sb_append(out, "%s", json->boolean ? "true" : "false");
            break;
        case JSON_NULL:
            sb_append(out, "null");
            break;
    }
}

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total_size = size * nmemb;

    char **response_ptr = (char **)userp;

    for (size_t i = 0; i < total_size; i++) {
        arrput(*response_ptr, ((char *)contents)[i]);
    }
    return total_size;
}


size_t header_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    size_t total_size = size * nitems;
    char **headers = (char **)userdata;

    // Append header data
    for (size_t i = 0; i < total_size; i++) {
        arrput(*headers, buffer[i]);
    }

    return total_size;
}


typedef struct {
    int32_t remaining;
    float retryAfter;
} RateLimitHeader;




void parse_header_to_json(Arena* arena, const char* headers, JsonValue* out) {
    const char* line_start = headers;
    const char* p = headers;

    while (*p) {
        if (*p == '\n' || *(p+1) == '\0') {
            const char* line_end = (*p == '\n') ? p : p + 1;
            const char* colon = memchr(line_start, ':', line_end - line_start);

            if (colon) {
                size_t name_len = colon - line_start;
                char* name = arena_alloc(arena, name_len + 1);
                memcpy(name, line_start, name_len);
                name[name_len] = '\0';

                const char* value_start = colon + 1;
                while (value_start < line_end && (*value_start == ' ' || *value_start == '\t')) {
                    value_start++;
                }

                const char* value_end = line_end;
                while (value_end > value_start && 
                       (*(value_end - 1) == ' ' || *(value_end - 1) == '\t' || *(value_end - 1) == '\r' || *(value_end - 1) == '\n')) {
                    value_end--;
                }

                size_t value_len = value_end - value_start;
                char* value = arena_alloc(arena, value_len + 1);
                memcpy(value, value_start, value_len);
                value[value_len] = '\0';

                json_add_child(out, name, json_new_nstring(arena, value, value_len));
            }

            line_start = p + 1;
        }
        p++;
    }
}



void get_request_json(const char* url, Arena* arena, JsonValue* out, RateLimitHeader* rlh){
    CURL *curl = curl_easy_init();
    CURLcode res;
    char* response = NULL;
    char* headers = NULL;
    curl_easy_setopt(curl, CURLOPT_CAINFO, CERTIFICATE_PATH);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);
    

    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Libcurl;Custom-Cjson/1.0");

    res = curl_easy_perform(curl);

    if(res == CURLE_OK){
        JsonValue json_headers = {0};
        json_init_object(&json_headers);
        arrput(headers, '\0');
        arrput(response, '\0');
        jsonStringLoad(response, arena, out);
        parse_header_to_json(arena, headers, &json_headers);

        if(shget(json_headers.object, "x-ratelimit-remaining") != NULL){
            rlh->remaining = atoi(shget(json_headers.object, "x-ratelimit-remaining")->string);
        }
        if(shget(json_headers.object, "x-ratelimit-retry-after") != NULL){
            rlh->retryAfter = atof(shget(json_headers.object, "x-ratelimit-retry-after")->string);
        }

        curl_easy_cleanup(curl);
        arrfree(response);
        arrfree(headers);
        return;
    }
    curl_easy_cleanup(curl);
    arrfree(response);
    arrfree(headers);
    return;
}

void fix_https(char *str) {
    char *src = str;
    char *dst = str;

    while (*src) {
        if (*src == '\\' && *(src + 1) == '/') {
            // Skip the backslash
            src++;
        }
        *dst++ = *src++;
    }
    *dst = '\0';  // Null-terminate the string
}

char* get_request_bytes(const char* url){
    CURL *curl = curl_easy_init();
    CURLcode res;
    char* response = NULL;
    curl_easy_setopt(curl, CURLOPT_CAINFO, CERTIFICATE_PATH);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Libcurl;Custom-Cjson/1.0");

    res = curl_easy_perform(curl);
    if(res == CURLE_OK){
        curl_easy_cleanup(curl);
        return response;
    }
    curl_easy_cleanup(curl);
    arrfree(response);
    return NULL;
}


bool save_finish_metadata(const char* filedir) {
    char tmpname[1024];
    snprintf(tmpname, sizeof(tmpname), "%s.tmp", filedir);

    FILE *file = fopen(tmpname, "w");
    if (file == NULL) {
        perror("Failed to create temporary file");
        return false;
    }

    if (fclose(file) != 0) {
        perror("Failed to close temporary file");
        return false;
    }

    if (rename(tmpname, filedir) != 0) {
        perror("Failed to atomically rename temporary file");
        return false;
    }

    return true;
}


size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(ptr, size, nmemb, stream);
}

int32_t download_chapter(const char* chapterId, Arena* arena, const char* main_dir){
    const char* base = "https://api.mangadex.org/at-home/server/";
    if(strlen(chapterId) != UUID4_SIZE){
        return -1;
    }
    size_t url_size = strlen(base) + strlen(chapterId) + 1; // +1 for null terminator
    char* url = arena_alloc(arena, url_size);
    snprintf(url, url_size, "%s%s", base, chapterId);
    JsonValue metadata = {0};
    RateLimitHeader ratelimit = {0};
    get_request_json(url, arena, &metadata, &ratelimit);
    if (ratelimit.remaining <= 0) {
        time_t now = time(NULL);
        time_t remaining = ratelimit.retryAfter - now + 5;
    
        if (remaining > 0) {
            atomic_store(&ratelimited, true);
            atomic_store(&downloading, false);
    
            DWORD ms = (DWORD)remaining * 1000;
    
            fprintf(stderr, "Ratelimited, sleeping for %ld ms\n", (long)ms);
            Sleep(ms);
    
            atomic_store(&ratelimited, false);
            atomic_store(&downloading, true);
        }
    }
    JsonValue* chapter = shget(metadata.object, "chapter");
    if(!chapter){
    	fprintf(stderr, "Chapter is null!\n");
    	return -1;
    }
    char* hash = shget(chapter->object, "hash")->string;
    char* baseUrl = shget(metadata.object, "baseUrl")->string;
    fix_https(baseUrl);
    JsonValue** pages = shget(chapter->object, "data")->array;

    size_t in_dir_size = strlen(main_dir) + 1 + strlen(chapterId) + 1;
	char* in_dir = arena_alloc(arena, in_dir_size);
	snprintf(in_dir, in_dir_size, "%s/%s", main_dir, chapterId);

    if(!nob_mkdir_if_not_exists(in_dir)) return -1;

    size_t num_requests = arrlenu(pages);
    CURL** easy_handles = malloc(num_requests * sizeof(CURL *));
    FILE** file_streams = calloc(num_requests, sizeof(FILE*));

    CURLM *multi = curl_multi_init();
    curl_multi_setopt(multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, 32);
    curl_multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS, 0);
    curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
    curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, 128);


    size_t finish_path_size = strlen(main_dir)+strlen(chapterId) + 11; // for / / null F I N I S H E D
    char* finish_path = arena_alloc(arena, finish_path_size);
    snprintf(finish_path, finish_path_size, "%s/%s/FINISHED", main_dir, chapterId);

    for (size_t i = 0; i < num_requests; i++) {
        size_t dest_url_size = strlen(baseUrl) + strlen(hash) + strlen(pages[i]->string) + 8;
        char* dest_url = arena_alloc(arena, dest_url_size);
        snprintf(dest_url, dest_url_size, "%s/data/%s/%s", baseUrl, hash, pages[i]->string);
        size_t file_path_size = strlen(main_dir)+strlen(chapterId)+strlen(pages[i]->string) + 3;
        char* file_path = arena_alloc(arena, file_path_size);
        snprintf(file_path, file_path_size, "%s/%s/%s", main_dir, chapterId, pages[i]->string);
        FILE* file_stream = fopen(file_path, "wb");
        if(!file_stream){
            fprintf(stderr, "Could not create new file %s\n", file_path);
            file_streams[i] = NULL;
            continue;
        }
        file_streams[i] = file_stream;

        easy_handles[i] = curl_easy_init();
        curl_easy_setopt(easy_handles[i], CURLOPT_URL, dest_url);
        curl_easy_setopt(easy_handles[i], CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(easy_handles[i], CURLOPT_WRITEDATA, file_stream);
        curl_easy_setopt(easy_handles[i], CURLOPT_USERAGENT, "Libcurl;Custom-Cjson/1.0");
        curl_easy_setopt(easy_handles[i], CURLOPT_PRIVATE, (void*)(uintptr_t)i);
        curl_easy_setopt(easy_handles[i], CURLOPT_CAINFO, CERTIFICATE_PATH);
        curl_easy_setopt(easy_handles[i], CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
        curl_easy_setopt(easy_handles[i], CURLOPT_DNS_CACHE_TIMEOUT, 600);

        curl_easy_setopt(easy_handles[i], CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(easy_handles[i], CURLOPT_TCP_KEEPIDLE, 30L);
        curl_easy_setopt(easy_handles[i], CURLOPT_TCP_KEEPINTVL, 15L);

        curl_easy_setopt(easy_handles[i], CURLOPT_FORBID_REUSE, 0L);
        curl_easy_setopt(easy_handles[i], CURLOPT_FRESH_CONNECT, 0L);

        curl_easy_setopt(easy_handles[i], CURLOPT_BUFFERSIZE, 1024 * 1024);   // 512 kbs

        curl_multi_add_handle(multi, easy_handles[i]);
    }

    int still_running;
    curl_multi_perform(multi, &still_running);

    while (still_running) {
        curl_multi_wait(multi, NULL, 0, MS_IN_SECONDS, NULL);
        CURLMcode mc = curl_multi_perform(multi, &still_running);
        if (mc != CURLM_OK) {
            fprintf(stderr, "curl_multi_perform error: %s\n", curl_multi_strerror(mc));
            break;
        }

        CURLMsg *msg;
        int msgs_left;
        while ((msg = curl_multi_info_read(multi, &msgs_left))) {
            if (msg->msg == CURLMSG_DONE) {
                CURL *handle = msg->easy_handle;

                uintptr_t idx;
                curl_easy_getinfo(handle, CURLINFO_PRIVATE, (void**)&idx);

                fclose(file_streams[idx]);
                file_streams[idx] = NULL;
                curl_multi_remove_handle(multi, handle);
                curl_easy_cleanup(handle);
            }
        }
    }
    
    free(easy_handles);
    for (size_t i = 0; i < num_requests; i++) {
        if(file_streams[i] != NULL){
            fclose(file_streams[i]);
        }
    }
    free(file_streams);
    curl_multi_cleanup(multi);
    if(!save_finish_metadata(finish_path)){
        fprintf(stderr, "Could not save metadata for cuuid: %s\n", chapterId);
    }
    return (int32_t)num_requests;
}

char* json_value_to_string(Arena* arena, JsonValue* value) {
    if (value->type == JSON_STRING) {
        size_t size = strlen(value->string);
        if(size == 0){
            char* string = arena_alloc(arena, 3);
            memcpy(string, "\"\"", 2);
            string[2] = '\0';
            return string;
        }
        char* string = arena_alloc(arena, size + 1);
        memcpy(string, value->string, size);
        string[size] = '\0';
        return string;
    } else if (value->type == JSON_NUMBER) {
        int size = snprintf(NULL, 0, "%g", value->number);
        char* string = arena_alloc(arena, size + 1);
        snprintf(string, size + 1, "%g", value->number);
        return string;
    }
    return NULL;
}

void* size_to_fit(Arena* arena, void* ptr, size_t* current_size, size_t size_to_fit){
    if (*current_size == 0) *current_size = 1;
    size_t new_size = *current_size;
    size_t old_size = *current_size;
    while(new_size < size_to_fit){
        new_size *= 2;
    }
    *current_size = new_size;
    return arena_realloc(arena, ptr, old_size, new_size);
}

char* concat_value(Arena* arena, char* url, size_t* size, const char* key, JsonValue* value) {
    char* value_string = json_value_to_string(arena, value);

    size_t url_len   = strlen(url);
    size_t key_len   = strlen(key);
    size_t val_len   = strlen(value_string);
    size_t extra_len = key_len + 1 /* '=' */ + val_len + 1 /* '&' */;

    size_t required_size = url_len + extra_len + 1; // +1 for '\0'
    if (required_size > *size) {
        url = size_to_fit(arena, url, size, required_size);
    }

    snprintf(url + url_len, *size - url_len, "%s=%s&", key, value_string);
    return url;
}

char* build_parameterized_url(Arena* arena, const char* baseUrl, JsonValue* params){
    size_t parameterized_url_size = 512;
    char* parameterized_url = arena_alloc(arena, parameterized_url_size);
    if (strlen(baseUrl) + 2 >= parameterized_url_size){
        parameterized_url = size_to_fit(arena, parameterized_url, &parameterized_url_size, strlen(baseUrl) + 2);
    }
    snprintf(parameterized_url, parameterized_url_size, "%s?", baseUrl);

    for(size_t i = 0; i < shlenu(params->object); i++){
        const char* key = params->object[i].key;
        if(params->object[i].value->type == JSON_OBJECT){
            fprintf(stderr, "Warn: Object is not supported in parameterization! Skipping\n");
            continue;
        }
        else if(params->object[i].value->type == JSON_ARRAY){
            for(size_t j = 0; j < arrlenu(params->object[i].value->array); j++){
                JsonValue* element = params->object[i].value->array[j];
                if(element->type == JSON_NUMBER || element->type == JSON_STRING){
                    parameterized_url = concat_value(arena, parameterized_url, &parameterized_url_size, key, element);
                }
            }
        }else{
            parameterized_url = concat_value(arena, parameterized_url, &parameterized_url_size, key, params->object[i].value);
        }

    }
    parameterized_url[strlen(parameterized_url)-1] = '\0';
    return parameterized_url;
}


typedef struct {
	char identifier[37];
	JsonValue* chapterInfo;
	JsonValue* databaseInfo;
} MangaDownloadJob;


JsonValue *json_dup(const JsonValue *src) {
    if (!src) return NULL;

    JsonValue *dst = malloc(sizeof(JsonValue));
    if (!dst) return NULL;

    dst->type = src->type;

    switch (src->type)
    {
        case JSON_ARRAY: {
            dst->array = NULL; // required before arrput
            size_t count = arrlenu(src->array);

            for (size_t i = 0; i < count; i++) {
                JsonValue *elem_copy = json_dup(src->array[i]);
                arrput(dst->array, elem_copy);
            }
            break;
        }

        case JSON_OBJECT: {
            dst->object = NULL; // required before shput

            size_t count = shlenu(src->object);
            for (size_t i = 0; i < count; i++) {
                const char *key = src->object[i].key;

                JsonValue *val_copy = json_dup(src->object[i].value);

                // shput duplicates the key automatically if necessary
                shput(dst->object, key, val_copy);
            }
            break;
        }

        case JSON_STRING:
            // If your strings are arena-allocated, do NOT strdup — just reuse
            // If they should be copied independently, use strdup:
            dst->string = src->string ? strdup(src->string) : NULL;
            break;

        case JSON_NUMBER:
            dst->number = src->number;
            break;

        case JSON_BOOL:
            dst->boolean = src->boolean;
            break;

        case JSON_NULL:
        default:
            break;
    }

    return dst;
}

typedef struct {
    MangaDownloadJob* buffer;
    int capacity;
    int head;
    int tail;
    int count;
    CRITICAL_SECTION lock;
    HANDLE dataAvailable;
} JobQueue;

// Initialize the queue
void initQueue(JobQueue* q, int capacity) {
    q->buffer = (MangaDownloadJob*)malloc(sizeof(MangaDownloadJob) * capacity);
    q->capacity = capacity;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    InitializeCriticalSection(&q->lock);
    q->dataAvailable = CreateEvent(NULL, FALSE, FALSE, NULL); // auto-reset event
}

// Destroy the queue
void destroyQueue(JobQueue* q) {
    free(q->buffer);
    DeleteCriticalSection(&q->lock);
    CloseHandle(q->dataAvailable);
}

// Push a job to the queue
bool pushQueue(JobQueue* q, MangaDownloadJob job) {
    EnterCriticalSection(&q->lock);
    if (q->count == q->capacity) {
        LeaveCriticalSection(&q->lock);
        return false; // queue full
    }
    q->buffer[q->tail] = job;
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;
    LeaveCriticalSection(&q->lock);
    SetEvent(q->dataAvailable); // signal that new data is available
    return true;
}

// Pop a job from the queue
bool popQueue(JobQueue* q, MangaDownloadJob* job) {
    EnterCriticalSection(&q->lock);
    if (q->count == 0) {
        LeaveCriticalSection(&q->lock);
        return false; // queue empty
    }
    *job = q->buffer[q->head];
    q->head = (q->head + 1) % q->capacity;
    q->count--;
    LeaveCriticalSection(&q->lock);
    return true;
}

DWORD WINAPI download_loop(LPVOID param) {
    JobQueue* queue = (JobQueue*)param;
    MangaDownloadJob job;
    bool has_job = false;
    Arena local_arena = {0};
    fprintf(stderr, "thread started!\n");

    curl_global_init(CURL_GLOBAL_ALL);
    while (!atomic_load(&stopped)) {
    	loop_start:
        if (atomic_load(&paused)) {
            if (has_job){
                pushQueue(queue, job);
                set_cwo("null");
                atomic_store(&job_chapters_downloaded, 0);
            }
            has_job = false;
            atomic_store(&downloading, false);
            Sleep(100);
            continue;
        }

        if (!has_job) {
		    if (!popQueue(queue, &job)) {
		        atomic_store(&downloading, false);
		        WaitForSingleObject(queue->dataAvailable, 100);
		        continue;
		    }
		    has_job = true;
		}

        has_job = true;
        atomic_store(&downloading, true);
        set_cwo(job.identifier);
        atomic_store(&job_chapters, arrlen(job.chapterInfo->array));

        for(size_t i = 0; i < arrlenu(job.chapterInfo->array); i++){
        	if(atomic_load(&paused) || atomic_load(&stopped)){
        		goto loop_start;
        	}
        	JsonPair* chapter = job.chapterInfo->array[i]->object;
        	JsonValue* id_val = shget(chapter, "id");
			if (!id_val || !id_val->string) continue;
			char* chapterId = id_val->string;
        	if(!chapterId){
        		continue;
        	}
        	JsonValue* pagesInDbJson = shget(job.databaseInfo->object, "pages_in_db");
        	JsonValue* records = shget(job.databaseInfo->object, "records");
        	JsonValue* chapterPagesInDb = shget(pagesInDbJson->object, chapterId);
        	if(chapterPagesInDb != NULL && records != NULL){
        		size_t record = (size_t)shget(records->object, chapterId)->number;
        		if(arrlenu(chapterPagesInDb->array) == record){
                    atomic_fetch_add(&job_chapters_downloaded, 1);
        			continue;
        		}
        	}

        	int32_t pages = download_chapter(chapterId, &local_arena, "downloads");
            if(pages < 0){
                fprintf(stderr, "Error while downloading %s", chapterId);
                atomic_fetch_add(&job_chapters_downloaded, 1);
                continue;
            }
            JsonValue* downloadedPages = arena_alloc(&local_arena, sizeof(JsonValue));
            json_init_array(downloadedPages);
            for(int32_t i = 0; i < pages; i++){
                json_add_child(downloadedPages, NULL, json_new_number(&local_arena, i+1));
            }
            json_add_child(pagesInDbJson, chapterId, downloadedPages);

            atomic_fetch_add(&job_chapters_downloaded, 1);
        }
        arena_reset(&local_arena);
        json_free(job.chapterInfo);
        json_free(job.databaseInfo);

        has_job = false;
        atomic_store(&downloading, false);
        set_cwo("null");
        atomic_store(&job_chapters_downloaded, 0);
    }
    fprintf(stderr, "thread ending!\n");
    curl_global_cleanup();
    arena_free(&local_arena);
    return 0;
}

JsonValue* handle_command(Arena* arena, JobQueue* queue, JsonValue* command){
    JsonValue* type = shget(command->object, "command");
    if(!type){
        fprintf(stderr, "command type is not present!\n");
        return NULL;
    }
    else if(strncmp(type->string, "exit", 4) == 0){
        atomic_store(&stopped, true);
        return NULL;
    }
    else if(strncmp(type->string, "pause", 5) == 0){
        atomic_store(&paused, true);
        return NULL;
    }else if(strncmp(type->string, "resume", 6) == 0){
        atomic_store(&paused, false);
        return NULL;
    }else if(strncmp(type->string, "status", 6) == 0){
        JsonValue* response = arena_alloc(arena, sizeof(JsonValue));
        JsonValue* queueJson = arena_alloc(arena, sizeof(JsonValue));
        char cwo_str[37];

        json_init_object(response);
        json_init_array(queueJson);

        get_cwo(cwo_str, 37);

        EnterCriticalSection(&queue->lock);

        for (int i = 0; i < queue->count; i++) {
            int index = (queue->head + i) % queue->capacity;
            MangaDownloadJob job = queue->buffer[index];
        
            json_add_child(queueJson, NULL, json_new_string(arena, job.identifier));
        }
        
        LeaveCriticalSection(&queue->lock);
        json_add_child(response, "type", json_new_string(arena, "status-response"));
        json_add_child(response, "paused",      json_new_bool(arena, atomic_load(&paused)));
        json_add_child(response, "ratelimited", json_new_bool(arena, atomic_load(&ratelimited)));
        json_add_child(response, "downloading", json_new_bool(arena, atomic_load(&downloading)));
        json_add_child(response, "queue", queueJson);
        json_add_child(response, "cwo", json_new_string(arena, cwo_str));
        json_add_child(response, "cwo_chapters", json_new_number(arena, atomic_load(&job_chapters)));
        json_add_child(response, "cwo_chapters_downloaded", json_new_number(arena, atomic_load(&job_chapters_downloaded)));

        return response;
    }else if(strncmp(type->string, "add-job", 7) == 0){
        JsonValue* data = shget(command->object, "data");
        JsonValue* response = arena_alloc(arena, sizeof(JsonValue));
        json_init_object(response);

        if(!data){
            fprintf(stderr, "Add-job dosent have all needed values!\n");
            json_add_child(response, "type", json_new_string(arena, "add-job-response"));
            json_add_child(response, "status", json_new_string(arena, "error"));
            json_add_child(response, "message", json_new_string(arena, "No data field provided"));
            return response;
        }

        if(queue->count >= queue->capacity-1){
            fprintf(stderr, "Queue is full\n");
            json_add_child(response, "type", json_new_string(arena, "add-job-response"));
            json_add_child(response, "status", json_new_string(arena, "error"));
            json_add_child(response, "message", json_new_string(arena, "Queue is full!"));
            return response;
        }

        JsonValue* chapterInfo = shget(data->object, "chapter_info");
        JsonValue* databaseInfo = shget(data->object, "database_info");

        if(!chapterInfo || !databaseInfo){
            fprintf(stderr, "chapter or database info is NULL!\n");
            json_add_child(response, "type", json_new_string(arena, "add-job-response"));
            json_add_child(response, "status", json_new_string(arena, "error"));
            json_add_child(response, "message", json_new_string(arena, "No chapterInfo or databaseInfo field provided"));
            return response;
        }

        MangaDownloadJob job = {0};
        const char* id = shget(data->object, "identifier")->string;
        strncpy(job.identifier, id, 36);
        job.identifier[36] = '\0';

        job.chapterInfo = json_dup(chapterInfo);
        job.databaseInfo = json_dup(databaseInfo);

        pushQueue(queue, job);
        json_add_child(response, "type", json_new_string(arena, "add-job-response"));
        json_add_child(response, "status", json_new_string(arena, "ok"));
        return response;
    }else if(strncmp(type->string, "pop-job", 7) == 0){
        JsonValue* data = shget(command->object, "data");
        JsonValue* response = arena_alloc(arena, sizeof(JsonValue));
        json_init_object(response);

        if(!data){
            fprintf(stderr, "Add-job dosent have all needed values!\n");
            json_add_child(response, "type", json_new_string(arena, "pop-job-response"));
            json_add_child(response, "status", json_new_string(arena, "error"));
            json_add_child(response, "message", json_new_string(arena, "No data field provided"));
            return response;
        }

        const char* id = shget(data->object, "identifier")->string;


        EnterCriticalSection(&queue->lock);

        for (int i = queue->count - 1; i >= 0; i--) {
            int index = (queue->head + i) % queue->capacity;
            MangaDownloadJob job = queue->buffer[index];
        
            if (strncmp(job.identifier, id, 36) == 0) {
                for (int j = i; j < queue->count - 1; j++) {
                    int from = (queue->head + j + 1) % queue->capacity;
                    int to   = (queue->head + j) % queue->capacity;
                    queue->buffer[to] = queue->buffer[from];
                }
                queue->tail = (queue->tail - 1 + queue->capacity) % queue->capacity;
                queue->count--;
            }
        }
        
        LeaveCriticalSection(&queue->lock);

        json_add_child(response, "type", json_new_string(arena, "pop-job-response"));
        json_add_child(response, "status", json_new_string(arena, "ok"));
        return response;
    }


    return NULL;
}



int main(void)
{
	Arena arena = {0};
	JobQueue queue = {0};
	initQueue(&queue, 100);
    init_cwo();
    set_cwo("null");

	nob_mkdir_if_not_exists("downloads");

	HANDLE thread = CreateThread(NULL, 0, download_loop, (void*)&queue, 0, NULL);
    if (thread == NULL) {
        fprintf(stderr, "Failed to create worker thread!\n");
        return 1;
    }

    JsonValue command = {0};
    uint32_t length;
    while (fread(&length, sizeof(length), 1, stdin) == 1) {
        char *buffer = malloc(length + 1);
        if (!buffer) {
            fprintf(stderr, "Memory allocation failed\n");
            return 1;
        }

        size_t read_bytes = fread(buffer, 1, length, stdin);
        if (read_bytes != length) {
            fprintf(stderr, "Incomplete read (%zu of %u bytes)\n", read_bytes, length);
            free(buffer);
            break;
        }

        buffer[length] = '\0';


        jsonStringLoad(buffer, &arena, &command);


        if(command.object == NULL){
            fprintf(stderr, "Recieved invalid buffer from proc\n");
            free(buffer);
            continue;
        }

        JsonValue* response = handle_command(&arena, &queue, &command);

        if(response){
            char *json_buf = NULL;

            json_print_compact(response, &json_buf);
            arrpush(json_buf, '\0');
    
            uint32_t resp_len = arrlenu(json_buf) - 1;
            fwrite(&resp_len, sizeof(resp_len), 1, stdout);
            fwrite(json_buf, 1, resp_len, stdout);
            fflush(stdout);
    
            arrfree(json_buf);
            json_free(response);
        }

        if(command.object){
            json_free(&command);
            memset(&command, 0, sizeof(JsonValue));
        }


        free(buffer);
        arena_reset(&arena);
        // If the command was exit we break 
        if(atomic_load(&stopped)){
            break;
        }
    }
	WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    arena_free(&arena);
    cleanup_cwo();
    destroyQueue(&queue);
    return 0;
}

