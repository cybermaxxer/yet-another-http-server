#ifndef SERVER_H
#define SERVER_H

#include <sys/types.h>

#define PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define IP "127.0.0.1"

typedef enum {
    STATE_METHOD,
    STATE_PATH,
    STATE_VERSION,
    STATE_HEADER_KEY,
    STATE_HEADER_VALUE,
    STATE_BODY,
    STATE_DONE,
    STATE_ERROR
} ParserState;

typedef struct header {
    char *key;
    char *value;
    struct header *next;
} Header;

typedef struct request {
    char *method;
    char *path;
    char *version;
    Header *headers;
    char *body;
} Request;

void free_headers(Header *header);
int parse_request(char *buffer, Request *request, ssize_t bytes_read);

#endif // SERVER_H
