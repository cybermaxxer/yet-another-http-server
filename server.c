#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define IP "127.0.0.1"

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
        const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"; //prepare a simple HTTP response to send back to the client, indicating a successful request (200 OK) and including a message body ("Hello, World!") with the appropriate Content-Length header
        write(client_fd, response, sizeof(response) - 1); //write() sends the response back to the client through the client socket (client_fd), using sizeof(response) - 1 to exclude the null terminator from the length of the data being sent
        close(client_fd);
    }
    close(server_fd);
    return 0;
}