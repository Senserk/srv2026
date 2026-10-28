#include "session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "--slot") == 0) {
        int quota = session_quota(atoi(argv[2]));
        if (quota < 0) {
            fprintf(stderr, "invalid slot\n");
            return 1;
        }
        printf("quota: %d\n", quota);
        return 0;
    }
    int reject_request = argc > 1 && strcmp(argv[1], "--reject") == 0;
    return handle_session(reject_request);
}
