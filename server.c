#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

void free_headers(Header *header) {
    while (header != NULL) { // iterate through the linked list of headers
        Header *next = header->next; // store the pointer to the next header
        free(header); // free the memory allocated for the current header
        header = next; // move to the next header in the list
    }
}

int parse_request(char *buffer, Request *request, ssize_t bytes_read) {
    request->headers = NULL;
    char *start = buffer; // pointer to the start of the buffer, which contains the raw HTTP request data
    char c; // character variable to store the current character from the buffer
    ParserState state = STATE_METHOD; // set the initial state of the parser to STATE_METHOD, indicating that we are expecting to parse the HTTP method first
    int content_length = 0; // variable to store the Content-Length value, initialized to 0
    int body_bytes_read = 0; // variable to keep track of the number of bytes read for the body, initialized to 0
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
                start = buffer + i + 1; // update the start pointer to point to the character after the space, which is the beginning of the requested path
                state = STATE_PATH; // transition to the STATE_PATH state to parse the requested path next
            }
                break;

            case STATE_PATH:
                if (c == ' ' ){
                buffer[i] = '\0'; // replace the space character with a null terminator to mark the end of the current token (e.g., method, path, version)
                request->path = start; // set the path field of the request structure to point to the start of the buffer, which now contains the requested path string
                if(request->path[0] != '/') { // validate that the path starts with a forward slash, which is required for valid HTTP requests
                    state = STATE_ERROR; // invalid path
                }
                state = STATE_VERSION; // transition to the STATE_VERSION state to parse the HTTP version next
                start = buffer + i + 1; // update the start pointer to point to the character after the space, which is the beginning of the HTTP version
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
                    if(strcmp(start, "HTTP/1.1") != 0) { // validate that the HTTP version is "HTTP/1.1", which is required for valid HTTP requests
                        state = STATE_ERROR; // invalid HTTP version
                    }
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
                    start = buffer + i + 2; // update the start pointer to point to the character after the colon, which is the beginning of the header value
                }

                else if (c == '\r' && buffer[i + 1] == '\n' && (buffer+i) == start) { // check if the current character is a carriage return and the next character is a newline, indicating the end of the headers section
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
                    start = buffer + i + 2; // update the start pointer to point to the character after the CRLF sequence, which is the beginning of the body (if any)
                    i=i+1; // increment the index to skip over the newline character, as it has already been processed in the state transition
                    buffer[i] = '\0'; // replace the carriage return character
                    }
                    else{ // if the Content-Length header was found but has a non-positive value, indicating an error in the request
                        state = STATE_ERROR; // transition to the STATE_ERROR state to indicate that there was an error during request parsing
                    }   
                }
                break;
            //stopped here CHECKPOINT: AUG 2, 11:12 2026
            case STATE_HEADER_VALUE:
                if(c == '\r' && buffer[i + 1] == '\n') { // check if the current character is a carriage return and the next character is a newline, indicating the end of the header value
                    buffer[i] = '\0'; // replace the carriage return character with a null terminator
                    i=i+1; // increment the index to skip over the newline character, as it
                    if (request->headers->key && strcmp(request->headers->key, "Content-Length") == 0) { // check if the current header key is "Content-Length"
                        content_length = atoi(start); // convert the header value string to an integer and store it in the content_length variable
                    }
                    request->headers->value = start; // set the value field of the new Header structure to point to the start of the buffer, which now contains the header value string
                    request->headers->next = NULL; // set the next field of the new Header structure
                    state = STATE_HEADER_KEY;
                    start = buffer + i + 1; // update the start pointer to point to the character after the CRLF sequence, which is the beginning of the next header key (if any)
                }
                break;

            case STATE_BODY:
                body_bytes_read++; // increment the count of bytes read for the body
                if (body_bytes_read >= content_length) { // check if the number of bytes read for the body is greater than or equal to the expected content length
                    buffer[i] = '\0'; // replace the current character with a null terminator to mark the end of the body
                    request->body = start; // set the body field of the request structure to point to the start of the buffer, which now contains the HTTP body string
                    start = buffer + i + 1; // update the start pointer to point to the character after the body, which is the end of the request
                    state = STATE_DONE;
                }
                else if (i == bytes_read - 1) { // check if we have reached the end of the buffer and still haven't read the entire body
                    state = STATE_ERROR; // transition to the STATE_ERROR state to indicate that there was an
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
        ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE); //read() reads data from the client socket (client_fd) into the buffer, up to BUFFER_SIZE bytes, and returns the number of bytes read, which is stored in bytes_read
        if (bytes_read < 0) {
            perror("read failed"); 
            exit(EXIT_FAILURE);
            
        }
        printf("Received message: %s\n", buffer);
        Request request; //create a Request structure to hold the parsed HTTP request data
        int isGoodRequest = parse_request(buffer, &request, bytes_read); //parse the raw HTTP request data in the buffer and populate the request structure with the parsed information, returning 0 for success or -1 for failure
        if (isGoodRequest == -1) { //check if the request parsing failed (isGoodRequest is -1), indicating a bad request
            const char response[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request"; //prepare a simple HTTP response to send back to the client, indicating a bad request (400 Bad Request) and including a message body ("Bad Request") with the appropriate Content-Length header
            write(client_fd, response, sizeof(response) - 1); //write() sends the response back to the client through the client socket (client_fd), using sizeof(response) - 1 to exclude the null terminator from the length of the data being sent
        }
        //learned a thing. i would previously print the whole parsed message without checking if it's a good or bad request
        //an appsec phiolosophy is to never trust the input, so if the request is bad, we should not print it out, because it could be malicious.
        //so what would happen is that if somebody sends a request with a very long path, it would print out the whole path, which could be a buffer overflow attack. so we should only print the parsed request if it's a good request.
        //not only buffer overflow, it'd iterate the linked list of headers, and if the headers are malformed, it could cause a segmentation fault or other undefined behavior. so we should only print the parsed request if it's a good request.
        //because the stuff isnt null terminated, so if the request is bad, it could cause a segmentation fault or other undefined behavior. so we should only print the parsed request if it's a good request.
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