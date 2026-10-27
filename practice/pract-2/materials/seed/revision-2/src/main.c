#include "session.h"

#include <string.h>

int main(int argc, char **argv) {
    int reject_request = argc > 1 && strcmp(argv[1], "--reject") == 0;
    return handle_session(reject_request);
}
