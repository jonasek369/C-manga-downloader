#define NOB_IMPLEMENTATION
#include "nob.h"

#define output "main.exe"


#define webp_incl "your/path/here/to/src"
#define webp_lib  "your/path/here/to/build"

#define curl_incl "your/path/here/to/include"
#define curl_lib  "your/path/here/to/lib"

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
        "-lsharpyuv",
        "-O2"
    );

    if (!nob_cmd_run_sync_and_reset(&cmd)) return 1;

    //nob_cmd_append(&cmd, "./" output);
    //if (!nob_cmd_run_sync_and_reset(&cmd)) return 1;

    return 0;
}
