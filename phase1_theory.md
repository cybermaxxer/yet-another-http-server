# phase 1: how tcp sockets and file descriptors actually work

these are my own notes from working through a raw c tcp server. writing down what i actually figured out, not a generic sockets tutorial.

## the misconceptions i had going in

i assumed a socket or file descriptor was some kind of network level object, something that gets passed between machines. it's not. an fd only exists inside one os's memory. `fd 3` on my server means nothing to the client, the client has its own `fd 3` pointing at something completely different.

i also assumed the server opens some kind of return connection to talk back to the client. it doesn't. there's one connection, the client opens it, both sides just read and write on their own end of the same thing.

so the picture i had (fds traveling across the wire, a separate "reply channel") was wrong. what actually identifies a connection over the network is ips and ports. the os is the thing translating incoming packets into local fds, invisibly, on both ends.

## the 4-tuple is the actual identity of a connection

every tcp connection on the internet is uniquely pinned down by four values:

- client ip
    
- client port
    
- server ip
    
- server port
    

as long as this exact combination is unique, the kernel can always tell which connection a packet belongs to. this is the thing that let me stop thinking about "the connection" as some abstract concept and start thinking about it as a specific 4 number key.

## client side vs. server side sockets

this is the part that actually clicked for me once i separated it into two distinct sockets doing two distinct jobs.

**the listening socket**, made by `listen()`:

- bound to one local port, e.g. port 80.
    
- its only job is to catch incoming connection requests.
    
- it never carries actual data.
    

**the connected socket**, returned by `accept()`:

- every time a client connects, `accept()` hands back a brand new fd, e.g. `fd 4`.
    
- this new fd is bound to that one specific client's 4 tuple: `(client_ip, 54321, server_ip, 80)`.
    
- the listening socket is now free again to accept the next client.
    

so a busy server has 1 listening fd and n connected fds, one per active client. the listening socket never touches data, it's purely a greeter.

## the 3 way handshake happens where i didn't expect

i originally thought `accept()` was the thing that performed the handshake. it's not, the handshake happens earlier and is triggered by the client's `connect()` call, not by the server calling `accept()`.

real order:

1. `socket()`, no handshake yet.
    
2. `bind()`, still nothing.
    
3. `listen()`, socket is now ready to receive connection attempts, still no handshake yet.
    
4. client calls `connect()`, this is what actually kicks off the handshake (client sends `SYN`, server sends `SYN-ACK`, client sends `ACK`).
    
5. once that final `ACK` lands, the kernel already considers the connection established and queues it.
    
6. `accept()` just dequeues an already finished connection and hands back a new fd.
    

so `accept()` is more like picking up a phone that's already ringing than dialing the call.

## the pointer cast that confused me: `(struct sockaddr *)&serv_addr`

this one took a while to actually understand instead of just copy pasting.

C

```
bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
```

breaking it into two separate operations:

- `&serv_addr` gets the raw memory address of my `sockaddr_in` struct, e.g. `0x7ffeefbff4a0`.
    
- `(struct sockaddr *)` doesn't move or touch a single bit at that address, it just tells the compiler "read the bytes at this address as if they were a `struct sockaddr`, not a `struct sockaddr_in`."
    

c has no inheritance, so back when bsd sockets were designed in the early 80s, there was no way to write one `bind()` that accepts ipv4, ipv6, and unix sockets as different "subclasses." instead they defined one generic base struct, and every protocol specific struct is laid out so the family field sits at the exact same offset, byte 0. `bind()` reads the first 2 bytes, sees `AF_INET`, and now knows it's actually holding a `sockaddr_in` underneath.

## threat modeling phase 1: trusting the wire

i got the basic socket loop working and it spammed a hardcoded `200 OK` response back. i honestly thought i was done with the networking part. i assumed parsing was just a matter of throwing some string split functions at the buffer.

i was wrong. tcp doesn't know what http is, and it definitely doesn't preserve message boundaries. an http request on the wire isn't a neat object; it's just a raw stream of untrusted bytes.

here is the exact code i wrote in phase 1 to handle incoming data:

C

```
char buffer[BUFFER_SIZE] = {0}; 
ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE); 
printf("Received message: %s\n", buffer);
```

this code assumes three incredibly dangerous things:

1. it assumes one `read()` equals one complete http request.
    
2. it assumes the client will nicely send text.
    
3. it blindly prints whatever was in the buffer to the console.
    

### the vulnerability: out-of-bounds read leading to segfault

in c, strings must end with a null terminator `\0`. i initialized the buffer with `{0}`, which means all 1024 bytes are `\0`.

but look at the `read()` call. i told it to read up to `BUFFER_SIZE` (1024 bytes). if a client sends exactly 1024 bytes of garbage, `read()` overwrites every single null terminator in that array.

then, i pass it to `printf("%s", buffer)`. `printf` doesn't know how big `buffer` is. it just starts at index 0 and iterates forward in memory until it hits a `\0`. because the client overwrote the last `\0`, `printf` iterates right out of bounds into memory it doesn't own.

### the exploit: breaking my own server

to exploit this, you don't even need a specialized tool. a few lines of python using raw tcp sockets will instantly crash the server.

Python

```
import socket

# create a payload of exactly 1024 'A's without any newlines or null bytes
payload = b'A' * 1024 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8080))
s.sendall(payload)
s.close()
```

the millisecond this payload hits the server, `read()` fills the buffer with 'A's. `printf` tries to print it, marches past the 1024th byte looking for a null terminator, hits unmapped memory, and triggers a `Segmentation fault (core dumped)`. remote denial of service (dos) in three lines of code.

### the patch: application-layer framing (leading into phase 2)

to fix this, i had to completely change my mental model. the actual job of the parser isn't "reading the request." it's forcing every single byte to prove it belongs in a valid request, and rejecting it the millisecond it fails.

first, we stop trusting `read()` to preserve boundaries. we have to accumulate bytes in a loop, capping the read at `BUFFER_SIZE - 1` to guarantee space for a null terminator.

C

```
while (bytes_read < BUFFER_SIZE - 1) {
    ssize_t chunk_read = read(client_fd, buffer + bytes_read, BUFFER_SIZE - 1 - bytes_read);
    // ... error checking ...
    bytes_read += chunk_read;
    buffer[bytes_read] = '\0'; // manually force the null terminator
    
    // check if we've hit \r\n\r\n 
    request_state = request_is_complete(buffer, bytes_read);
    if (request_state != 1) {
        break; 
    }
}
```

second, i learned to never trust the `printf`. printing unvalidated input is a massive security philosophy violation. in phase 2, i completely remove the raw `printf`. i now capture the state of the parser, and i only print the parsed method, path, and version if the explicit state machine gives the green light. if it's a bad request, i silently return an `HTTP/1.1 400 Bad Request` and don't log the malicious payload.

## checkpoint: phase 1 raw code

this is the vulnerable but functional phase 1 code before i tore out the monolithic loop to build the state machine parser.

```c
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
```