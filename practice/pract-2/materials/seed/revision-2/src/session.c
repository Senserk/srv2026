#include "session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *allocate_session(void) {
    char *session = malloc(64);
    if (session != NULL) {
        strcpy(session, "release-candidate-session");
    }
    return session;
}

int handle_session(int reject_request) {
    char *session = allocate_session();
    if (session == NULL) {
        return 2;
    }

    if (reject_request) {
        fprintf(stderr, "request rejected: %s\n", session);
        free(session);
    }

    puts("session closed");
    free(session);
    return reject_request ? 1 : 0;
}

static int quota[4] = {10, 20, 30, 40};

int session_quota(int slot) {
    return quota[slot];
}
