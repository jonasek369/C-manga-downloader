#define NOB_IMPLEMENTATION
#include "nob.h"

#define output "main.exe"

#define webp_incl "C:/Users/mato/Downloads/libwebp-1.6.0/src"
#define webp_lib  "C:/Users/mato/Downloads/libwebp-1.6.0/build"

#define curl_incl "C:/Users/mato/Downloads/curl-8.17.0_1-win64-mingw/include"
#define curl_lib  "C:/Users/mato/Downloads/curl-8.17.0_1-win64-mingw/lib"

int main(int argc, char **argv)
{
    NOB_GO_REBUILD_URSELF(argc, argv);
    Nob_Cmd cmd = {0};

    nob_cmd_append(&cmd, "gcc",
        "-I", webp_incl,
        "-I", curl_incl,
        "-L", webp_lib,
        "-L", curl_lib,
        "-g",
        "-Wall",
        "-Wextra",
        "-o", output,
        "main.c",
        "-lwebp",   // link webp
        "-lcurl",    // link curl
        "-lsharpyuv"
    );

    if (!nob_cmd_run_sync_and_reset(&cmd)) return 1;

    nob_cmd_append(&cmd, "./" output);
    if (!nob_cmd_run_sync_and_reset(&cmd)) return 1;

    return 0;
}
