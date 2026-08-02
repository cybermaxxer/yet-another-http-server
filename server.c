#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define IP "127.0.0.1"
#define MAX_HEADERS 1
typedef enum { // state machine of a parsing HTTP request
    STATE_METHOD, // waiting for the HTTP method (e.g., GET, POST)
    STATE_PATH, // waiting for the requested path (e.g., /index.html)
    STATE_VERSION, // waiting for the HTTP version (e.g., HTTP/1.1)
    STATE_HEADER_KEY, // waiting for the header key (e.g., Content-Type)
    STATE_HEADER_VALUE, // waiting for the header value (e.g., text/html)
    STATE_BODY, // waiting for the HTTP body (if any, e.g., in POST requests)
    STATE_DONE, // finished parsing the request
    STATE_ERROR // encountered an error while parsing the request
} ParserState;
typedef struct header{
    char *key; // pointer to the header key string
    char *value; // pointer to the header value string
    struct header *next; // pointer to the next header in the linked list
} Header;
typedef struct request{
    char *method; // pointer to the HTTP method string
    char *path; // pointer to the requested path string
    char *version; // pointer to the HTTP version string
    Header *headers; // pointer to the linked list of headers
    char *body; // pointer to the HTTP body string (if any)
} Request;
parse_request(char *buffer, Request *request, ssize_t bytes_read) {
    request->headers = NULL;
    char *start = buffer; // pointer to the start of the buffer, which contains the raw HTTP request data
    char c; // character variable to store the current character from the buffer
    ParserState state = STATE_METHOD; // set the initial state of the parser to STATE_METHOD, indicating that we are expecting to parse the HTTP method first
    for(int i = 0; i < bytes_read; i++){ // iterate through each character in the buffer, which contains the raw HTTP request data received from the client
        c = buffer[i]; // get the current character from the buffer
        switch(state) { // switch statement to handle different parsing states based on the current state of the parser
            case STATE_METHOD:
                if (c == ' ' ){
                buffer[i] = '\0'; // replace the space character with a null terminator to mark the end of the current token (e.g., method, path, version)
                request->method = start; // set the method field of the request structure to point to the start of the buffer, which now contains the HTTP method string
                start = buffer + i + 1; // update the start pointer to point to the character after the space, which is the beginning of the requested path
                state = STATE_PATH; // transition to the STATE_PATH state to parse the requested path next
            }
                break;
            case STATE_PATH:
                if (c == ' ' ){
                buffer[i] = '\0'; // replace the space character with a null terminator to mark the end of the current token (e.g., method, path, version)
                request->path = start; // set the path field of the request structure to point to the start of the buffer, which now contains the requested path string
                state = STATE_VERSION; // transition to the STATE_VERSION state to parse the HTTP version next
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
                state = STATE_HEADER_KEY; // transition to the STATE_HEADER_KEY state to parse the header key next
                request->version = start; // set the version field of the request structure to point to the start of the buffer, which now contains the HTTP version string
                start = buffer + i + 2; // update the start pointer to point to the character after the CRLF sequence, which is the beginning of the header key
                i=i+1; // increment the index to skip over the newline character, as it has already been processed in the state transition
                buffer[i] = '\0'; // replace the carriage return character with a null terminator to mark the end of the current token (e.g., method, path, version)
            }
                break;

            case STATE_HEADER_KEY:
            if(c == ':'){
                buffer[i] = '\0'; // replace the colon character with a null terminator to mark the end of the header key
                Header *new_header = malloc(sizeof(Header)); // allocate memory for a new Header structure to store the parsed header key-value pair
                new_header->key = start; // set the key field of the new Header structure to point to the start of the buffer, which now contains the header key string
                new_header->next = request->headers; // link the new Header structure to the existing
                request->headers = new_header; // update the headers pointer in the request structure to point to the new Header structure, effectively adding it to the front of the linked list of headers
                state = STATE_HEADER_VALUE; // transition to the STATE_HEADER_VALUE state to parse the header value next
                start = buffer + i + 1; // update the start pointer to point to the character after the colon, which is the beginning of the header value
            }

            else if (c == '\r' && buffer[i + 1] == '\n' && (buffer+i) == start) { // check if the current character is a carriage return and the next character is a newline, indicating the end of the headers section
                //"I'm standing at the beginning of the token, and the very next thing I see is \r\n" can only be true 
                //if there was nothing between the start of the token and the \r\n, because if there had been something there, 
                //you wouldn't still be at the beginning, you'd have walked past it already.
                state = STATE_DONE; // transition to the STATE_DONE state to indicate that the request parsing is complete
                start = buffer + i + 2; // update the start pointer to point to the character after the CRLF sequence, which is the beginning of the body (if any)
                i=i+1; // increment the index to skip over the newline character, as it has already been processed in the state transition
                buffer[i] = '\0'; // replace the carriage return character

            }
            break;
            //stopped here CHECKPOINT: AUG 2, 11:12 2026
            case STATE_HEADER_VALUE:
            if(c == '\r' && buffer[i + 1] == '\n') { // check if the current character is a carriage return and the next character is a newline, indicating the end of the header value
                buffer[i] = '\0'; // replace the carriage return character with a null terminator
                i=i+1; // increment the index to skip over the newline character, as it
                request->headers->value = start; // set the value field of the new Header structure to point to the start of the buffer, which now contains the header value string
                request->headers->next = NULL; // set the next field of the new Header structure
            }
                break;

            case STATE_BODY:
                break;

            case STATE_DONE:
                break;

            case STATE_ERROR:
                break;
        }
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
        ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE); //read() reads data from the client socket (client_fd) into the buffer, up to BUFFER_SIZE bytes, and returns the number of bytes read, which is stored in bytes_read
        if (bytes_read < 0) {
            perror("read failed"); 
            exit(EXIT_FAILURE);
            
        }
        printf("Received message: %s\n", buffer);
        Request request; //create a Request structure to hold the parsed HTTP request data
        parse_request(buffer, &request, bytes_read); //parse the HTTP request received from the client, extracting the method, path, version, headers, and body into a structured format for further processing
        const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"; //prepare a simple HTTP response to send back to the client, indicating a successful request (200 OK) and including a message body ("Hello, World!") with the appropriate Content-Length header
        write(client_fd, response, sizeof(response) - 1); //write() sends the response back to the client through the client socket (client_fd), using sizeof(response) - 1 to exclude the null terminator from the length of the data being sent
        close(client_fd);
    }
    close(server_fd);
    return 0;
}
