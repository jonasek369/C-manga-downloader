#include <stdio.h>
#include <curl/curl.h>
#include <windows.h>
#include <stdatomic.h>
#include <webp/encode.h>
#include <webp/types.h>

#include "test.h" // output from LMDX-download-job as string

#define NOB_IMPLEMENTATION
#include "nob.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#include "json_parser.h"




#define CERTIFICATE_PATH "curl-ca-bundle.crt"
#define UUID4_SIZE 36
#define CHAPTER_DOWNLOAD_URL_SIZE 40


typedef struct {
    char *data;      // arr of char*
    char *file_path; // file path
} request_buffer;

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total_size = size * nmemb;

    char **response_ptr = (char **)userp;

    for (size_t i = 0; i < total_size; i++) {
        arrput(*response_ptr, ((char *)contents)[i]);
    }
    return total_size;
}


size_t write_image_callback(char *contents, size_t size, size_t nmemb, void *userdata) {
    size_t total_size = size * nmemb;

    request_buffer *buf = (request_buffer *)userdata;
    for (size_t i = 0; i < total_size; i++) {
        arrput((*buf).data, ((char *)contents)[i]);
    }

    return total_size;
}


void get_request_json(const char* url, Arena* arena, JsonValue* out){
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
    	arrput(response, '\0');
        jsonStringLoad(response, arena, out);
        curl_easy_cleanup(curl);
        arrfree(response);
        return;
    }
    curl_easy_cleanup(curl);
    arrfree(response);
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

bool save_webp_to_file(const char* filedir, uint8_t* buffer, size_t size){
    FILE *file = fopen(filedir, "wb");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }
    size_t written = fwrite(buffer, sizeof(uint8_t), size, file);
    if(written != size){
        perror("Failed to write the complete buffer");
        fclose(file);
        return 1;
    }
    fclose(file);
    return 0;
}

bool save_finish_metadata(const char* filedir){
    FILE *file = fopen(filedir, "w");
    if (file == NULL) {
        perror("Failed to create file");
        return 1;
    }
    fclose(file);
}


void page_download_callback(const char* path, char* data) {
    int width, height, channels;

    size_t data_size = arrlenu(data);
    uint8_t* pixels = stbi_load_from_memory((uint8_t*)data, (int)data_size, &width, &height, &channels, 4);
    if (!pixels) {
        printf("Failed to decode image\n");
        return;
    }

    uint8_t* webp_data;
    /* TODO: Change compression */
    size_t output_size  = WebPEncodeRGBA(pixels, width, height, width * 4, 80, &webp_data);
    if (output_size == 0) {
        printf("Failed to encode WebP\n");
        stbi_image_free(pixels);
        return;
    }

    save_webp_to_file(path, webp_data, output_size);

    stbi_image_free(pixels);
    WebPFree(webp_data);
}


void download_chapter(const char* chapterId, Arena* arena, const char* main_dir){
    const char* base = "https://api.mangadex.org/at-home/server/";
    if(strlen(chapterId) != UUID4_SIZE){
        return;
    }
    size_t url_size = strlen(base) + strlen(chapterId) + 1; // +1 for null terminator
    char* url = arena_alloc(arena, url_size);
    // TODO: Check for rate limiting
    snprintf(url, url_size, "%s%s", base, chapterId);
    JsonValue metadata = {0};
    get_request_json(url, arena, &metadata);
    JsonValue* chapter = shget(metadata.object, "chapter");
    if(!chapter){
    	fprintf(stderr, "Chapter is null!\n");
    	return;
    }
    char* hash = shget(chapter->object, "hash")->string;
    char* baseUrl = shget(metadata.object, "baseUrl")->string;
    fix_https(baseUrl);
    JsonValue** pages = shget(chapter->object, "data")->array;

    size_t in_dir_size = strlen(main_dir) + 1 + strlen(chapterId) + 1;
	char* in_dir = arena_alloc(arena, in_dir_size);
	snprintf(in_dir, in_dir_size, "%s/%s", main_dir, chapterId);

    if(!nob_mkdir_if_not_exists(in_dir)) return;

    size_t num_requests = arrlenu(pages);
    CURL **easy_handles = malloc(num_requests * sizeof(CURL *));
    request_buffer *buffers = calloc(num_requests, sizeof(request_buffer));

    curl_global_init(CURL_GLOBAL_ALL);
    CURLM *multi = curl_multi_init();

    size_t finish_path_size = strlen(main_dir)+strlen(chapterId) + 11; // for / / null F I N I S H E D
    char* finish_path = arena_alloc(arena, finish_path_size);
    snprintf(finish_path, finish_path_size, "%s/%s/FINISHED", main_dir, chapterId);

    for (size_t i = 0; i < num_requests; i++) {
        size_t dest_url_size = strlen(baseUrl) + strlen(hash) + strlen(pages[i]->string) + 8;
        char* dest_url = arena_alloc(arena, dest_url_size);
        snprintf(dest_url, dest_url_size, "%s/data/%s/%s", baseUrl, hash, pages[i]->string);
        size_t file_path_size = strlen(main_dir)+strlen(chapterId)+strlen(pages[i]->string) + 3;
        buffers[i].file_path = arena_alloc(arena, file_path_size);
        snprintf(buffers[i].file_path, file_path_size, "%s/%s/%s", main_dir, chapterId, pages[i]->string);

        easy_handles[i] = curl_easy_init();
        curl_easy_setopt(easy_handles[i], CURLOPT_URL, dest_url);
        curl_easy_setopt(easy_handles[i], CURLOPT_WRITEFUNCTION, write_image_callback);
        curl_easy_setopt(easy_handles[i], CURLOPT_WRITEDATA, &buffers[i]);
        curl_easy_setopt(easy_handles[i], CURLOPT_USERAGENT, "Libcurl;Custom-Cjson/1.0");
        curl_easy_setopt(easy_handles[i], CURLOPT_CAINFO, CERTIFICATE_PATH);
        curl_multi_add_handle(multi, easy_handles[i]);
    }

    int still_running;
    curl_multi_perform(multi, &still_running);

    while (still_running) {
        curl_multi_poll(multi, NULL, 0, 200, NULL);
        curl_multi_perform(multi, &still_running);

        CURLMsg *msg;
        int msgs_left;
        while ((msg = curl_multi_info_read(multi, &msgs_left))) {
            if (msg->msg == CURLMSG_DONE) {
                CURL *handle = msg->easy_handle;

                for (size_t i = 0; i < num_requests; i++) {
                    if (easy_handles[i] == handle) {
                        page_download_callback(buffers[i].file_path, buffers[i].data);
                        arrfree(buffers[i].data);
                        curl_multi_remove_handle(multi, handle);
                        curl_easy_cleanup(handle);
                        break;
                    }
                }
            }
        }
    }
    
    free(easy_handles);
    free(buffers);
    curl_multi_cleanup(multi);
    curl_global_cleanup();
    save_finish_metadata(finish_path);
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
            printf("Warn: Object is not supported in parameterization! Skipping\n");
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

atomic_bool paused = false;
atomic_bool stopped = false;
atomic_bool downloading = false;
atomic_bool ratelimited = false;

atomic_int job_chapters_downloaded = 0;
atomic_int job_chapters = 0;

typedef struct {
	char identifier[37];
	JsonValue* chapterInfo;
	JsonValue* databaseInfo;
} MangaDownloadJob;


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
    SetEvent(q->dataAvailable); // signal that new data is available
    LeaveCriticalSection(&q->lock);
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
    printf("thread started!\n");
    while (!atomic_load(&stopped)) {
    	loop_start:
        if (atomic_load(&paused)) {
            if (has_job) pushQueue(queue, job);
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
        		int record = (int)shget(records->object, chapterId)->number;
        		if(arrlen(chapterPagesInDb) == record){
        			continue;
        		}
        	}
        	/* TODO: Add more checks */
        	download_chapter(chapterId, &local_arena, "downloads");
        }
        arena_reset(&local_arena);
    }
    printf("thread ending!\n");
    arena_free(&local_arena);
    return 0;
}

int main(void)
{
	Arena arena = {0};
	JobQueue queue = {0};
	initQueue(&queue, 100);
	/*
	  TODO: Add IPC with the main program
	*/

	JsonValue json_data = {0};
	jsonStringLoad(full_data, &arena, &json_data);

	MangaDownloadJob job = {0};
	memcpy(job.identifier, shget(json_data.object, "identifier")->string, 36);
	job.identifier[36] = '\0';
	job.chapterInfo = shget(shget(json_data.object, "chapter_info")->object, "data");
	job.databaseInfo = shget(json_data.object, "database_info");

	pushQueue(&queue, job);

	nob_mkdir_if_not_exists("downloads");

	HANDLE thread = CreateThread(NULL, 0, download_loop, (void*)&queue, 0, NULL);
    if (thread == NULL) {
        printf("Failed to create worker thread!\n");
        return 1;
    }

	WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    arena_free(&arena);
    destroyQueue(&queue);
    return 0;
}