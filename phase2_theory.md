# phase 2: parsing http without trusting the wire

these are my notes from writing a raw http/1.1 parser from scratch. no frameworks, no regex, just iterating over an array of bytes.

## the misconception i had going in

in phase 1, i wrote a loop that called `read()` exactly once, blindly printed whatever was in the buffer to the console, and spammed a hardcoded `200 OK` response back. i honestly thought i was done with the networking part.

i've always thought of http requests as structured objects—you ask a framework for `request.headers["Content-Length"]` and it just hands it to you. i assumed parsing was just a matter of throwing some string split functions at the buffer.

i was wrong. tcp doesn't know what http is, and it definitely doesn't preserve message boundaries. an http request on the wire isn't a neat object; it's just a raw stream of untrusted bytes. the actual job of the parser isn't "reading the request." it's forcing every single byte to prove it belongs in a valid request, and rejecting it the millisecond it fails.

## splitting the monolith: `.c`, `.h`, and `#ifndef`

as the logic grew from a simple `while(1)` loop to a full parser, dumping everything in `main()` became impossible to manage. so, i split the project into `server.h` and `server.c`.

the `.h` (header) file is the contract. it holds my `ParserState` enum, my `Header` and `Request` structs, and the function signatures. the `.c` file contains the actual logic.

one thing that tripped me up early on was "include guards" at the top of the header file:

C

```
#ifndef SERVER_H
#define SERVER_H
// ... definitions ...
#endif // SERVER_H
```

if i write multiple `.c` files that all `#include "server.h"`, the compiler would see my `Request` struct definition multiple times and throw a redefinition error. the `#ifndef` directive guarantees the structs are defined exactly once per compilation pass.

## threat modeling phase 2: the parsing engine

building this parser hammered home the core appsec mindset: you don't write code for when things go right. you write code for when the bytes on the wire are actively trying to destroy your server. here are the exact vulnerabilities i introduced, exploited, and patched while building the state machine.

### threat model 1: the string split trap

**the vulnerability:** my instinct was to use `strtok` to find spaces and newlines. but `strtok` uses static internal state and is non-reentrant. it expects perfectly formatted c-strings. **the exploit:** an attacker opens a socket and sends 10,000 "A"s without a single space or newline. `strtok` keeps walking memory looking for a delimiter, steps right off the edge of the buffer, and crashes the server. **the patch:** i dropped `strtok` completely and built an explicit state machine. i defined states like `STATE_METHOD` and `STATE_PATH`, and i read the buffer exactly one character at a time in a `for` loop using a `switch(state)` block. every single byte dictates exactly what the next legal state can be. if i'm in `STATE_METHOD` and see an unsupported method, i immediately drop to `STATE_ERROR`.

### threat model 2: memory exhaustion (infinite headers)

**the vulnerability:** http headers are dynamic, so i built a linked list to store them using `malloc(sizeof(Header))`. **the exploit:** an attacker connects and sends `a: b\r\n` in an infinite loop. my code faithfully `malloc`s a new node for every single line. eventually, the server runs out of ram, the os kills the process, and we have a catastrophic denial of service (dos). **the patch:** i added a hard cap. i defined `MAX_HEADERS` to 16 and added a `header_count` variable. if a client exceeds 16 headers, the parser immediately breaks to `STATE_ERROR`.

### threat model 3: content-length integer overflow

**the vulnerability:** parsing the body size sounds simple, but string-to-integer conversion is full of holes. **the exploit:** an attacker sends `Content-Length: -100` or an absolutely massive number. naive string conversion translates this into integer overflow, resulting in undersized buffer allocations or massive memory grabs. **the patch:** i switched to `strtol`, which lets you catch exactly where the parsing stopped. i explicitly verify that the pointer moved, that no garbage characters were left behind, and that the parsed length is strictly between 0 and `INT_MAX`.

### threat model 4: http request smuggling (ambiguity)

**the vulnerability:** the 2019 request smuggling attacks happened because proxy servers and backend servers disagreed on where a request ended. the core issue is usually receiving both `Content-Length` and `Transfer-Encoding: chunked`. **the exploit:** an attacker sends both headers. if the proxy prioritizes `Transfer-Encoding` but my backend prioritizes `Content-Length`, the attacker can hide a second, fully-formed malicious request inside the body of the first one. **the patch:** the fix isn't to write clever code to figure out which header is right; the fix is to refuse the ambiguity. i track `hasTransfer` and `hasLength`. if i see multiple framing headers, or if i see `Transfer-Encoding` in this phase, i don't resolve it—i just reject the request outright with `STATE_ERROR`.

## in-place mutation and memory leaks

instead of allocating new memory for strings like the method and path, i use an in-place mutation trick. when my state machine hits a space, i do `buffer[i] = '\0'`. i just overwrite spaces and carriage returns with null terminators in the original buffer, and point my `Request` struct fields to offsets inside that one buffer. it's fast and avoids massive memory overhead.

but for the headers, i still used a dynamically allocated linked list. this meant i had to clean up error paths. error paths are where most memory leaks hide, so whether the request succeeds or fails, i pass the list to my new `free_headers()` function before closing the connection.

C

```
void free_headers(Header *header) {
    while (header != NULL) { 
        Header *next = header->next; 
        free(header); 
        header = next; 
    }
}
```

## transitioning to phase 3: high concurrency

right now, the parser is hardened. the server won't crash on bad formatting, it won't be smuggled, and it bounds its memory usage. but there is still one glaring architectural flaw: the main loop.

currently, it's a single-client blocking loop. if an attacker opens a connection and just sits there sending one byte every ten seconds (a slowloris attack), no other client can connect. the entire server hangs.

in phase 3, i'll be tearing out this blocking architecture to build for high concurrency. the focus shifts entirely to kernel-level multiplexing (using `epoll` or `kqueue`), preventing data races in shared memory, and ensuring the server can handle thousands of concurrent, adversarial connections safely.

## checkpoint: the full code so far

**`server.h`**

C

```
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
```

**`server.c`**

C

```
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

void free_headers(Header *header) {
    while (header != NULL) { // iterate through the linked list of headers
        Header *next = header->next; // store the pointer to the next header
        free(header); // free the memory allocated for the current header
        header = next; // move to the next header in the list
    }
}

static int request_is_complete(const char *buffer, ssize_t bytes_read) {
    const char *header_end = strstr(buffer, "\r\n\r\n");
    if (header_end == NULL) {
        return 1;
    }

    ssize_t header_end_offset = (ssize_t)(header_end - buffer);
    if (header_end_offset >= BUFFER_SIZE) {
        return -1;
    }

    char header_copy[BUFFER_SIZE];
    memcpy(header_copy, buffer, (size_t)header_end_offset);
    header_copy[header_end_offset] = '\0';

    long content_length = 0;
    int saw_content_length = 0;

    char *line = header_copy;
    while (*line != '\0') {
        char *line_end = strstr(line, "\r\n");
        if (line_end == NULL) {
            break;
        }

        size_t line_length = (size_t)(line_end - line);
        if (line_length == strlen("Content-Length:") && strncmp(line, "Content-Length:", line_length) == 0) {
            char *value = line + line_length;
            while (*value == ' ') {
                value++;
            }

            char *end = NULL;
            long parsed_length = strtol(value, &end, 10);
            if (end == value || *end != '\0' || parsed_length < 0 || parsed_length > INT_MAX) {
                return -1;
            }

            content_length = parsed_length;
            saw_content_length = 1;
        }

        line = line_end + 2;
    }

    if (!saw_content_length) {
        return 0;
    }

    return bytes_read >= header_end_offset + 4 + content_length ? 0 : 1;
}

int parse_request(char *buffer, Request *request, ssize_t bytes_read) {
    request->headers = NULL;
    char *start = buffer; // pointer to the start of the buffer, which contains the raw HTTP request data
    char c; // character variable to store the current character from the buffer
    ParserState state = STATE_METHOD; // set the initial state of the parser to STATE_METHOD, indicating that we are expecting to parse the HTTP method first
    int content_length = 0; // variable to store the Content-Length value, initialized to 0
    int body_bytes_read = 0; // variable to keep track of the number of bytes read for the body, initialized to 0
    int hasTransfer = 0; // variable to keep track of whether the Transfer-Encoding or Content-Length header has been encountered, initialized to 0
    int hasLength = 0; // variable to keep track of whether the Content-Length header has been encountered, initialized to 0
    int header_count = 0; // keep the number of headers small so one request cannot exhaust memory
    const int MAX_HEADERS = 16;
    for(int i = 0; i < bytes_read; i++){ // iterate through each character in the buffer, which contains the raw HTTP request data received from the client
        c = buffer[i]; // get the current character from the buffer
        switch(state) { // switch statement to handle different parsing states based on the current state of the parser
            case STATE_METHOD:
                if (c == ' ' ){
                buffer[i] = '\0'; // replace the space character with a null terminator to mark the end of the current token (e.g., method, path, version)
                request->method = start; // set the method field of the request structure to point to the start of the buffer, which now contains the HTTP method string
                // validate method token early to reject unsupported methods
                if (!(strcmp(request->method, "GET") == 0 || strcmp(request->method, "POST") == 0)) {
                    state = STATE_ERROR; // unsupported method
                }
                else{
                    start = buffer + i + 1; // update the start pointer to point to the character after the space, which is the beginning of the requested path                    
                    state = STATE_PATH; // transition to the STATE_PATH state to parse the requested path next
                }
            }
                break;

            case STATE_PATH:
                if (c == ' ' ){
                buffer[i] = '\0'; // replace the space character with a null terminator to mark the end of the current token (e.g., method, path, version)
                request->path = start; // set the path field of the request structure to point to the start of the buffer, which now contains the requested path string
                if(request->path[0] != '/') { // validate that the path starts with a forward slash, which is required for valid HTTP requests
                    state = STATE_ERROR; // invalid path
                }
                else{
                    state = STATE_VERSION; // transition to the STATE_VERSION state to parse the HTTP version next
                    start = buffer + i + 1; // update the start pointer to point to the character after the space, which is the beginning of the HTTP version
                }
            }
                break;
            case STATE_VERSION:
                char next_char; // declare a variable to hold the next character in the buffer for checking the end of the line
                if(i+1 < bytes_read){ // check if the next character index is within the bounds of the buffer to avoid accessing out-of-bounds memory
                    next_char = buffer[i + 1]; // get the next character in the buffer to check for the end of the line
                }
                else{
                    next_char = '\0'; // if the next character index is out of bounds, set next_char to a null character to avoid undefined behavior
                }
                if (c == '\r' && next_char == '\n') { // check if the current character is a carriage return and the next character is a newline, indicating the end of the
                    buffer[i] = '\0'; // replace the carriage return character with a null terminator to mark the end of the current token (e.g., method, path, version)
                    printf("HTTP Version: %s\n", start); // print the parsed HTTP version to the console for debugging purposes
                    if(strcmp(start, "HTTP/1.1") != 0) { // validate that the HTTP version is "HTTP/1.1", which is required for valid HTTP requests
                        state = STATE_ERROR; // invalid HTTP version
                        break;
                    }
                    else{
                        state = STATE_HEADER_KEY; // transition to the STATE_HEADER_KEY state to parse the header key next
                        request->version = start; // set the version field of the request structure to point to the start of the buffer, which now contains the HTTP version string
                        i=i+1; // increment the index to skip over the newline character, as it has already been processed in the state transition
                        start = buffer + i + 1; // update the start pointer to point to the character after the CRLF sequence, which is the beginning of the header key
                        buffer[i] = '\0'; // replace the carriage return character with a null terminator to mark the end of the current token (e.g., method, path, version)
                    }
            }
                break;

            case STATE_HEADER_KEY:
                if(c == ':'){
                    if (header_count >= MAX_HEADERS) {
                        state = STATE_ERROR;
                        break;
                    }
                    buffer[i] = '\0'; // replace the colon character with a null terminator to mark the end of the header key
                    Header *new_header = malloc(sizeof(Header)); // allocate memory for a new Header structure to store the parsed header key-value pair
                    if (new_header == NULL) {
                        state = STATE_ERROR;
                        break;
                    }
                    new_header->key = start; // set the key field of the new Header structure to point to the start of the buffer, which now contains the header key string
                    new_header->next = request->headers; // link the new Header structure to the existing
                    request->headers = new_header; // update the headers pointer in the request structure to point to the new Header structure, effectively adding it to the front of the linked list of headers
                    header_count++; // count this header before moving on to the value
                    state = STATE_HEADER_VALUE; // transition to the STATE_HEADER_VALUE state to parse the header value next
                    start = buffer + i + 2; // update the start pointer to point to the character after the colon, which is the beginning of the header value
                }

                else if (c == '\r' && i + 1 < bytes_read && buffer[i + 1] == '\n' && (buffer+i) == start) { // check if the current character is a carriage return and the next character is a newline, indicating the end of the headers section
                    //"I'm standing at the beginning of the token, and the very next thing I see is \r\n" can only be true 
                    //if there was nothing between the start of the token and the \r\n, because if there had been something there, 
                    //you wouldn't still be at the beginning, you'd have walked past it already.
                    if(content_length == 0){ // check if the Content-Length header was not found, indicating that there is no body to read
                        buffer[i] = '\0'; // replace the carriage return character with a null terminator to mark the end of the headers section
                        request->body = NULL; // set the body field of the request structure to NULL, indicating that there is no body
                        start = buffer + i + 2; // update the start pointer to point to the character after the CRLF sequence, which is the end of the request
                        state = STATE_DONE; // transition to the STATE_DONE state to indicate that the request parsing is complete
                    }
                    else if(content_length > 0){ // check if the Content-Length header was found and has a positive value, indicating that there is a body to read
                    state = STATE_BODY; // transition to the STATE_BODY state to indicate that the request parsing is complete
                    i=i+1 ; // increment the index to skip over the newline character, as it has already been processed in the state transition
                    start = buffer + i + 1; // update the start pointer to point to the character after the CRLF sequence, which is the beginning of the body (if any)
                    buffer[i] = '\0'; // replace the carriage return character
                    }
                    else{ // if the Content-Length header was found but has a non-positive value, indicating an error in the request
                        state = STATE_ERROR; // transition to the STATE_ERROR state to indicate that there was an error during request parsing
                    }   
                }
                break;
            //stopped here CHECKPOINT: AUG 2, 11:12 2026
            case STATE_HEADER_VALUE:
                if(i+1 >= bytes_read){ // check if the next character index is within the bounds of the buffer to avoid accessing out-of-bounds memory
                    state = STATE_ERROR; // transition to the STATE_ERROR state to indicate that there was an error during request parsing
                    continue; // skip the rest of the loop iteration and move to the next character in the buffer       
                    }
                else{
                if(i + 1 < bytes_read && c == '\r' && buffer[i + 1] == '\n') { // check if the current character is a carriage return and the next character is a newline, indicating the end of the header value
                    buffer[i] = '\0'; // replace the carriage return character with a null terminator
                    i=i+1; // increment the index to skip over the newline character, as it
                    if (request->headers->key && strcmp(request->headers->key, "Content-Length") == 0) { // check if the current header key is "Content-Length"
                        if(hasTransfer || hasLength) { // reject mixed framing and duplicate Content-Length headers
                            state = STATE_ERROR; // transition to the STATE_ERROR state to indicate that there was an error during request parsing
                            break;
                        }
                        char *end = NULL;
                        long parsed_length = strtol(start, &end, 10);
                        if (end == start || *end != '\0' || parsed_length < 0 || parsed_length > INT_MAX) {
                            state = STATE_ERROR;
                            break;
                        }
                        content_length = (int)parsed_length; // only accept a clean nonnegative decimal length
                        hasLength = 1; // set the hasLength variable to indicate that the Content-Length header has been encountered
                    }
                    if (request->headers->key && strcmp(request->headers->key, "Transfer-Encoding") == 0) { // check if the current header key is "Transfer-Encoding"
                        state = STATE_ERROR; // reject Transfer-Encoding in phase 2 to avoid request smuggling ambiguity
                        break;
                    }
                    request->headers->value = start; // set the value field of the new Header structure to point to the start of the buffer, which now contains the header value string
                    state = STATE_HEADER_KEY;
                    start = buffer + i + 1; // update the start pointer to point to the character after the CRLF sequence, which is the beginning of the next header key (if any)
                }
            }
                break;

            case STATE_BODY:
                body_bytes_read++; // increment the count of bytes read for the body
                if (body_bytes_read >= content_length) { // check if the number of bytes read for the body is greater than or equal to the expected content length
                    buffer[i+1] = '\0'; // replace the current character with a null terminator to mark the end of the body
                    request->body = start; // set the body field of the request structure to point to the start of the buffer, which now contains the HTTP body string
                    start = buffer + i + 1; // update the start pointer to point to the character after the body, which is the end of the request
                    state = STATE_DONE;
                }
                else if (i == bytes_read - 1) { // check if we have reached the end of the buffer and still haven't read the entire body
                    printf("Incomplete body received\n"); // print a message to the console for debugging purposes
                    state = STATE_ERROR; // transition to the STATE_ERROR state to indicate that there was an error
                }
                    break;
                    
            case STATE_DONE:
                return 0; // return 0 to indicate successful parsing of the request
                break;
            case STATE_ERROR:
                return -1; // return -1 to indicate an error during request parsing
                break;

            default:
                return -1; // return -1 to indicate an error during request parsing
                break;
        }
    }
    if(state == STATE_DONE){ // check if the parser has reached the STATE_DONE state after processing all characters in the buffer
        return 0; // return 0 to indicate successful parsing of the request
    }
    else{
        return -1; // return -1 to indicate an error during request parsing
    }
}
int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0); //AF_INET for IPv4, SOCK_STREAM for TCP, 0 for default protocol
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) { // Allow reuse of the address, if the server is down, the port can be reused immediately
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in address; //server address structure
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(IP);
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) { // Bind the socket to the specified IP and port, 
        perror("bind failed"); //struct sockaddr_in is cast to struct sockaddr because bind() expects a struct sockaddr pointer, basically cating sockaddr_in to sockaddr is a way to treat the specific address structure as a more generic one, allowing the bind function to work with different types of addresses.
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    while(1){
        struct sockaddr_in client_address; // create a new sockaddr_in structure to hold the client's address information
        socklen_t client_address_len = sizeof(client_address); //store the size of the client address structure in a variable of type socklen_t, which is used to specify the length of the address structure when calling accept()
        int client_fd = accept(server_fd, (struct sockaddr *)&client_address, &client_address_len); //accept() waits for an incoming connection, and when a client connects, it fills in the client_address structure with the client's address information and returns a new socket file descriptor (client_fd) that can be used to communicate with the client.
        if (client_fd < 0) { 
            perror("accept failed");
            exit(EXIT_FAILURE);
        }

        char buffer[BUFFER_SIZE] = {0}; //prepare a buffer to read the incoming data from the client, initializing it to zero to ensure it starts empty
        ssize_t bytes_read = 0;
        int request_state = 1;
        while (bytes_read < BUFFER_SIZE - 1) {
            ssize_t chunk_read = read(client_fd, buffer + bytes_read, BUFFER_SIZE - 1 - bytes_read); //read() reads data from the client socket into the buffer, appending any new bytes after what is already buffered
            if (chunk_read < 0) {
                perror("read failed");
                exit(EXIT_FAILURE);
            }
            if (chunk_read == 0) {
                break;
            }

            bytes_read += chunk_read;
            buffer[bytes_read] = '\0';
            request_state = request_is_complete(buffer, bytes_read);
            if (request_state != 1) {
                break;
            }
        }
        printf("Bytes read: %zd\n", bytes_read); //print the number of bytes read from the client socket to the console for debugging purposes
        if (bytes_read == 0 || request_state == 1) {
            request_state = -1;
        }
        printf("Received message: %s\n", buffer);
        Request request; //create a Request structure to hold the parsed HTTP request data
        int isGoodRequest = request_state == 0 ? parse_request(buffer, &request, bytes_read) : -1; //parse the raw HTTP request data once the accumulated bytes are enough for a complete request
        if (isGoodRequest == -1) { //check if the request parsing failed (isGoodRequest is -1), indicating a bad request
            const char response[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request"; //prepare a simple HTTP response to send back to the client, indicating a bad request (400 Bad Request) and including a message body ("Bad Request") with the appropriate Content-Length header
            write(client_fd, response, sizeof(response) - 1); //write() sends the response back to the client through the client socket (client_fd), using sizeof(response) - 1 to exclude the null terminator from the length of the data being sent
        }
        else {
           printf("Parsed request: method=%s, path=%s, version=%s\n", request.method, request.path, request.version);
            for(Header *header = request.headers; header != NULL; header = header->next) { //iterate through the linked list of headers in the request structure, printing each header's key and value
                printf("Header: %s: %s\n", header->key, header->value);
        }
            printf("Body: %s\n", request.body ? request.body : "(no body)"); //print the body of the request if it exists, or indicate that there is no body            
            printf("Request is valid.\n"); //print a message indicating that the request was successfully parsed and is valid
            const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"; //prepare a simple HTTP response to send back to the client, indicating a successful request (200 OK) and including a message body ("Hello, World!") with the appropriate Content-Length header
            write(client_fd, response, sizeof(response) - 1); //write() sends the response back to the client through the client socket (client_fd), using sizeof(response) - 1 to exclude the null terminator from the length of the data being sent
        }

        free_headers(request.headers); //free the memory allocated for the linked list of headers in the request structure to avoid memory leaks
        if(close(client_fd) < 0) { //close the client socket to free up resources and indicate that the server is done communicating with the client, checking for errors during the close operation
            perror("just in case, im paranoid, ikr");   //this will print if for there was no need for this close.     
        }
    }
    return 0;
}
```