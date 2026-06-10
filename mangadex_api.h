typedef struct {
    int32_t remaining;
    int64_t retryAfter;
} RateLimitHeader;


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


char* json_value_to_string(JsonValue* value){
    if(value->type == JSON_STRING){
        return value->string;
    }
    if(value->type == JSON_NUMBER){
        if(value->flags & HAS_FRACTION){
            return nob_temp_sprintf("%f", value->number);
        }else{
            return nob_temp_sprintf("%ld", value->integer);
        }
    }
    fprintf(stderr, "[Error] Trying to get string value of type that is not either number or string\n");
    return NULL;
}


char* build_parameterized_url(const char* baseUrl, JsonValue* params){
    Nob_String_Builder sb = {0};
    nob_sb_append_cstr(&sb, baseUrl);
    nob_sb_append_cstr(&sb, "?");



    for(size_t i = 0; i < shlenu(params->object); i++){
        const char* key = params->object[i].key;
        if(params->object[i].value->type == JSON_OBJECT){
            fprintf(stderr, "[Warning] Object is not supported in parameterization! Skipping\n");
            continue;
        }
        else if(params->object[i].value->type == JSON_ARRAY){
            for(size_t j = 0; j < arrlenu(params->object[i].value->array); j++){
                JsonValue* element = params->object[i].value->array[j];
                if(element->type == JSON_NUMBER || element->type == JSON_STRING){
                    nob_sb_append_cstr(&sb, key);
                    nob_sb_append_cstr(&sb, "=");
                    nob_sb_append_cstr(&sb, json_value_to_string(element));
                    nob_sb_append_cstr(&sb, "&");
                }
            }
        }else{
            nob_sb_append_cstr(&sb, key);
            nob_sb_append_cstr(&sb, "=");
            nob_sb_append_cstr(&sb, json_value_to_string(params->object[i].value));
            nob_sb_append_cstr(&sb, "&");
        }

    }
    // -1 because we need to remove the leading "&"
    sb.items[--sb.count] = '\0';
    return strdup(sb.items);
}

void parse_header_to_json(const char* headers, JsonValue* out) {
    const char* line_start = headers;
    const char* p = headers;

    while (*p) {
        if (*p == '\n' || *(p+1) == '\0') {
            const char* line_end = (*p == '\n') ? p : p + 1;
            const char* colon = memchr(line_start, ':', line_end - line_start);

            if (colon) {
                size_t name_len = colon - line_start;
                char* name = malloc(name_len + 1);
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

                json_add_child(out, name, json_new_nstring(value_start, value_len));
                free(name);
            }

            line_start = p + 1;
        }
        p++;
    }
}

void get_request_json(const char* url, JsonValue* out, RateLimitHeader* rlh){
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
        jsonStringLoad(response, out);
        parse_header_to_json(headers, &json_headers);

        if(shget(json_headers.object, "x-ratelimit-remaining") != NULL){
            rlh->remaining = atoi(shget(json_headers.object, "x-ratelimit-remaining")->string);
        }
        if(shget(json_headers.object, "x-ratelimit-retry-after") != NULL){
            rlh->retryAfter = atoll(shget(json_headers.object, "x-ratelimit-retry-after")->string);
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


JsonValue* get_manga_aggregate(const char* uuid, const char* language){
    JsonValue* aggregate = malloc(sizeof(JsonValue));
    RateLimitHeader rlh = {0};
    if(!aggregate){
        return NULL;
    }

    Nob_String_Builder aggregate_url_sb = {0};
    nob_sb_append_cstr(&aggregate_url_sb, "https://api.mangadex.org/manga/");
    nob_sb_append_cstr(&aggregate_url_sb, uuid);
    nob_sb_append_cstr(&aggregate_url_sb, "/aggregate");
    nob_sb_append_null(&aggregate_url_sb);

    JsonValue* params = malloc(sizeof(JsonValue));
    json_init_object(params);
    JsonValue* langs = malloc(sizeof(JsonValue));
    json_init_array(langs);
    json_add_child(langs, NULL, json_new_string(language));

    json_add_child(params, "translatedLanguage[]", langs);
    json_add_child(params, "includeUnavailable", json_new_integer(0));

    char* paramed_url = build_parameterized_url(aggregate_url_sb.items, params); 

    get_request_json(paramed_url, aggregate, &rlh);
    free(paramed_url);

    json_free(params);
    NOB_FREE(aggregate_url_sb.items);
    return aggregate;
}


JsonValue* get_manga_info(const char* uuid){
    JsonValue* info = malloc(sizeof(JsonValue));
    RateLimitHeader rlh = {0};
    if(!info){
        return NULL;
    }

    Nob_String_Builder info_url_sb = {0};
    nob_sb_append_cstr(&info_url_sb, "https://api.mangadex.org/manga/");
    nob_sb_append_cstr(&info_url_sb, uuid);
    nob_sb_append_null(&info_url_sb);
    get_request_json(info_url_sb.items, info, &rlh);
    NOB_FREE(info_url_sb.items);
    return info;
}


void fix_https(char *str) {
    char *src = str;
    char *dst = str;

    while (*src) {
        if (*src == '\\' && *(src + 1) == '/') {
            src++;
        }
        *dst++ = *src++;
    }
    *dst = '\0';
}

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(ptr, size, nmemb, stream);
}

void download_chapter(const char* chapter_id, const char* path, const char* volume_str, const char* chapter_str, uint8_t* state){
    Nob_String_Builder download_url = {0};
    nob_sb_append_cstr(&download_url, "https://api.mangadex.org/at-home/server/");
    nob_sb_append_cstr(&download_url, chapter_id);
    nob_sb_append_null(&download_url);

    Nob_String_Builder path_builder = {0};
    nob_sb_append_cstr(&path_builder, path);
    nob_sb_append_cstr(&path_builder, "/");
    nob_sb_append_cstr(&path_builder, volume_str);
    nob_sb_append_null(&path_builder);

    JsonValue* metadata = malloc(sizeof(JsonValue));

    if(!nob_mkdir_if_not_exists(path_builder.items)){
        *state = DOWNLOAD_STATE_FS_ERROR;
        goto defer;
    }

    path_builder.count--; // remove NULL terminator
    nob_sb_append_cstr(&path_builder, "/");
    nob_sb_append_cstr(&path_builder, chapter_str);
    nob_sb_append_null(&path_builder);

    if(!nob_mkdir_if_not_exists(path_builder.items)){
        *state = DOWNLOAD_STATE_FS_ERROR;
        goto defer;
    }

    Nob_File_Paths paths = {0};
    nob_read_entire_dir(path_builder.items, &paths);
    // 2 because theres always ".." and "."
    if(paths.count > 2){
        *state = DOWNLOAD_STATE_ALREADY_EXISTS;
        NOB_FREE(paths.items);
        goto defer;
    }
    NOB_FREE(paths.items);

    RateLimitHeader ratelimit = {0};

    get_request_json(download_url.items, metadata, &ratelimit);

    if (ratelimit.remaining <= 0) {
        time_t now = time(NULL);
    
        int64_t wait = (int64_t)ratelimit.retryAfter - (int64_t)now;
    
        if (wait < 0) wait = 0;
        wait += 5;
    
        sleep_seconds((unsigned int)wait);
        *state = DOWNLOAD_STATE_RATELIMITED;
        goto defer;
    }
    JsonValue* chapter = NULL;
    JsonValue* hash = NULL;
    JsonValue* baseUrl = NULL;
    JsonValue* data = NULL;

    TYPE_CHECK_FIELD_GET(metadata, chapter, JSON_OBJECT);
    TYPE_CHECK_FIELD_GET(chapter, hash, JSON_STRING);
    TYPE_CHECK_FIELD_GET(metadata, baseUrl, JSON_STRING);
    fix_https(baseUrl->string);
    TYPE_CHECK_FIELD_GET(chapter, data, JSON_ARRAY);
    
    size_t num_requests = arrlenu(data->array);
    CURL** easy_handles = malloc(num_requests * sizeof(CURL *));
    FILE** file_streams = calloc(num_requests, sizeof(FILE*));

    CURLM *multi = curl_multi_init();
    curl_multi_setopt(multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, 32);
    curl_multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS, 0);
    curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
    curl_multi_setopt(multi, CURLMOPT_MAXCONNECTS, 128);

    for(size_t i = 0; i < num_requests; i++){
        Nob_String_Builder page_url = {0};
        Nob_String_Builder page_path = {0};

        nob_sb_append_cstr(&page_url, baseUrl->string);
        nob_sb_append_cstr(&page_url, "/data/");
        nob_sb_append_cstr(&page_url, hash->string);
        nob_sb_append_cstr(&page_url, "/");
        nob_sb_append_cstr(&page_url, data->array[i]->string);
        nob_sb_append_null(&page_url);


        nob_sb_append_cstr(&page_path, path_builder.items);
        nob_sb_append_cstr(&page_path, "/");
        nob_sb_append_cstr(&page_path, data->array[i]->string);
        nob_sb_append_null(&page_path);

        FILE* fs = fopen(page_path.items, "wb");
        if(!fs){
            fprintf(stderr, "[Error] Vol. %s Ch. %s page %zu Could not create file for image\n", volume_str, chapter_str, i+1);
            file_streams[i] = NULL;
            continue;
        }
        file_streams[i] = fs;

        easy_handles[i] = curl_easy_init();
        curl_easy_setopt(easy_handles[i], CURLOPT_URL, page_url.items);
        curl_easy_setopt(easy_handles[i], CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(easy_handles[i], CURLOPT_WRITEDATA, fs);
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


        NOB_FREE(page_path.items);
        NOB_FREE(page_url.items);
    }

    int still_running;
    curl_multi_perform(multi, &still_running);

    while (still_running) {
        curl_multi_wait(multi, NULL, 0, 1000, NULL);
        CURLMcode mc = curl_multi_perform(multi, &still_running);
        if (mc != CURLM_OK) {
            fprintf(stderr, "[Error] curl_multi_perform error: %s\n", curl_multi_strerror(mc));
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
    *state = DOWNLOAD_STATE_OK;
defer:
    NOB_FREE(download_url.items);
    NOB_FREE(path_builder.items);
    json_free(metadata);
    return;
}