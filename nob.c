#define NOB_IMPLEMENTATION
#include "../thirdparty/nob.h"

#define output "main"



int main(int argc, char **argv)
{
    NOB_GO_REBUILD_URSELF(argc, argv);
    Nob_Cmd cmd = {0};

    nob_cmd_append(&cmd, "gcc",
        "-g",
        "-Wall",
        "-Wextra",
        "-o", output,
        "main.c",
        "./tiny_queue/tiny_queue.c",
        "-lcurl"
    );

    if (!nob_cmd_run_sync_and_reset(&cmd)) return 1;

    //nob_cmd_append(&cmd, "./" output);
    //if (!nob_cmd_run_sync_and_reset(&cmd)) return 1;

    return 0;
}
