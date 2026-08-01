# phase 1: how tcp sockets and file descriptors actually work

these are my own notes from working through a raw c tcp server. writing down what i actually figured out, not a generic sockets tutorial.

## the misconceptions i had going in

i assumed a socket or file descriptor was some kind of network level object, something that gets passed between machines. it's not. an fd only exists inside one os's memory. `fd 3` on my server means nothing to the client, the client has its own `fd 3` pointing at something completely different.

i also assumed the server opens some kind of return connection to talk back to the client. it doesn't. there's one connection, the client opens it, both sides just read and write on their own end of the same thing.

so the picture i had (fds traveling across the wire, a separate "reply channel") was wrong. what actually identifies a connection over the network is ips and ports. the os is the thing translating incoming packets into local fds, invisibly, on both ends.

## the 4-tuple is the actual identity of a connection

every tcp connection on the internet is uniquely pinned down by four values:

```
(client ip, client port, server ip, server port)
```

as long as this exact combination is unique, the kernel can always tell which connection a packet belongs to. this is the thing that let me stop thinking about "the connection" as some abstract concept and start thinking about it as a specific 4 number key.

## client side: one socket for the whole conversation

1. `socket()` creates an fd, say `fd 3`.
2. `connect(server_ip, server_port)` is called.
3. the os auto assigns the client an ephemeral (random high number) port, something like `54321`.
4. that same `fd 3` is used to both send and receive for the entire life of the connection.

nothing fancy here, one fd, one job.

## server side: one listener, many workers

this is the part that actually clicked for me once i separated it into two distinct sockets doing two distinct jobs.

**the listening socket**, made by `listen()`:
- bound to one local port, e.g. port 80.
- its only job is to catch incoming connection requests. it never carries actual data.

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
4. client calls `connect()`, this is what actually kicks off the handshake:
   - client to server: `SYN`
   - server to client: `SYN-ACK`
   - client to server: `ACK`
5. once that final `ACK` lands, the kernel already considers the connection established and queues it.
6. `accept()` just dequeues an already finished connection and hands back a new fd. it doesn't wait through the handshake itself, the handshake already happened before `accept()` returns.

so `accept()` is more like picking up a phone that's already ringing than dialing the call.

## how the server os actually routes an incoming packet

when a packet lands on the server, the kernel does two separate lookups, at two separate layers.

**layer 3, routing:** checks if the destination ip matches this machine and picks the right network interface. this is the `ip route` step.

**layer 4, socket lookup:** hashes the packet's 4 tuple `(client ip, client port, server ip, server port)` and checks it against a table of established connections.

- if there's a match, the data goes straight into that connection's dedicated socket buffer, e.g. `fd 4`. this is the fast path.
- if there's no match, e.g. this is a fresh `SYN`, it falls through to a second table, the listening sockets, matched only on destination ip and port. if that matches, the request goes to the listening socket to start a handshake.
- if neither table has a match, the kernel sends back a `TCP RST` and drops it, this is what a closed port looks like from the outside.

this whole lookup runs in roughly constant time because it's a hash table, not a scan, so it doesn't get slower as more connections pile up. it's also how discord, chrome, and my own server can all sit on the same network card without any cross talk, their 4 tuples hash to different buckets.

## the pointer cast that confused me: `(struct sockaddr *)&serv_addr`

this one took a while to actually understand instead of just copy pasting.

```c
bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
```

breaking it into two separate operations:

- `&serv_addr` gets the raw memory address of my `sockaddr_in` struct, e.g. `0x7ffeefbff4a0`.
- `(struct sockaddr *)` doesn't move or touch a single bit at that address, it just tells the compiler "read the bytes at this address as if they were a `struct sockaddr`, not a `struct sockaddr_in`."

so the cast changes how the bytes get interpreted, not what the bytes are.

**why does the api force this at all?** c has no inheritance, so back when bsd sockets were designed in the early 80s, there was no way to write one `bind()` that accepts ipv4, ipv6, and unix sockets as different "subclasses." instead they defined one generic base struct:

```c
struct sockaddr {
    unsigned short sa_family;   // e.g. AF_INET, AF_INET6
    char           sa_data[14]; // protocol specific bytes
};
```

and every protocol specific struct, like `sockaddr_in`, is laid out so the `sa_family` / `sin_family` field sits at the exact same offset, byte 0. that's the trick that makes the whole thing safe: `bind()` reads the first 2 bytes, sees `AF_INET`, and now knows it's actually holding a `sockaddr_in` underneath, so it can read the port and ip correctly from there.

i also wondered why they didn't just use `void *` since that's the normal generic pointer in c. two reasons: `void *` wasn't standardized until ansi c (c89), which came after bsd sockets already existed, and `void *` can't be dereferenced directly anyway, you'd still need a cast at the point of use. so the explicit struct pointer cast was effectively doing manual polymorphism before c had any real way to express it.

## the mental model i'm keeping from this

- a memory address is just a number pointing into ram.
- a pointer's type is not a property of the memory, it's an instruction to the compiler on how to read the bytes at that address.
- casting `(struct sockaddr *)&serv_addr` changes the second thing, never the first.
