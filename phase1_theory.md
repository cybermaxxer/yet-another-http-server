# How TCP Sockets and File Descriptors Work

## 1. Core Misconceptions Cleared
* **Sockets / File Descriptors (FDs) are local abstractions.** They exist only inside an operating system's memory. FD numbers (like `fd 3` or `fd 5`) never travel across the network.
* **No "return connection" is opened.** The client initiates a single connection. The server does not open a second connection back to the client.
* **The client never knows about the server's FDs.** Both sides communicate using IP addresses and port numbers. The OS translates network packets to local FDs invisibly.

---

## 2. The Network Identity: The 4-Tuple
Every TCP connection across the internet is uniquely identified by four values:
$$\text{(Client IP, Client Port, Server IP, Server Port)}$$

As long as these four values are unique, the network stack knows exactly where every packet belongs.

---

## 3. Client vs. Server Lifecycle

### Client Side (1 Socket)
1. Creates a socket (`fd = 3`).
2. Calls `connect(Server_IP, Server_Port)`.
3. The client's OS automatically assigns an ephemeral (random high-numbered) port (e.g., `54321`).
4. Uses this **same FD** for the entire lifespan of the connection to both send and receive data.

### Server Side (1 Listening Socket + N Connected Sockets)
1. **Listening Socket (`listen()`):**
   * Binds to a local port (e.g., Port `80`).
   * Acts as the "greeter." Its only job is to receive new connection requests.
2. **Connected Socket (`accept()`):**
   * When a client connects, `accept()` returns a **brand-new file descriptor** (e.g., `fd = 4`).
   * This new FD is bound specifically to that client's 4-tuple: `(Client_IP, 54321, Server_IP, 80)`.
   * This leaves the listening socket free to keep accepting new incoming clients.

---

## 4. How the Server OS Routes Traffic

When a packet arrives at the server, two distinct OS lookups occur:

1. **`ip route` (Layer 3 - Network Layer):**
   Checks if the packet's destination IP matches the host machine and chooses the correct physical network interface.
2. **TCP Socket Hash Table (Layer 4 - Transport Layer):**
   Hashes the packet's 4-tuple `[Client IP, Client Port, Server IP, Server Port]`.
   * **If a match exists:** Pushes the incoming data into the receive buffer of the dedicated connected socket (e.g., `fd = 4`).
   * **If no match exists (e.g., TCP SYN):** Hands the connection request to the listening socket (e.g., `fd = 3`).

---

## 5. Summary Flow Diagram

```text
CLIENT                                      SERVER
-------------------------------------------------------------------------
1. Socket created (fd 3)
   OS assigns port 54321

2. connect(Server_IP:80) ───[ SYN ]───► 3. Listening Socket (fd 3)
                                           OS completes handshake
                                           accept() returns NEW Socket (fd 4)

4. send() / recv() on fd 3 ◄─── Data ───► 5. send() / recv() on fd 4
   (Talks to Server_IP:80)                 (Bound to Client_IP:54321)

Here is a clean, structured Markdown summary of the TCP Socket Lookup Algorithm to save for your notes:
```markdown
# TCP Socket Lookup Algorithm (`__inet_lookup`)

## Overview
The TCP Socket Lookup Algorithm is the kernel mechanism that inspects every incoming TCP packet and routes it to its corresponding local Socket / File Descriptor (FD) in $O(1)$ constant time.

---

## 1. The Key: The 4-Tuple
Every active TCP packet is uniquely identified by four header fields:

$$\text{4-Tuple} = (\text{Source IP}, \text{Source Port}, \text{Destination IP}, \text{Destination Port})$$

* **Established connections** are indexed by all 4 values.
* **Listening sockets** are indexed only by destination `(IP, Port)`.

---

## 2. The 2-Phase Algorithm Flow

```text
Incoming Packet
       │
       ▼
1. Extract 4-Tuple ──► Hash(4-Tuple)
       │
       ▼
2. Check Established Table (ehash)
       │
       ├──► [MATCH FOUND] ──► Push payload to Active Socket FD (e.g., Discord, Chrome, Client A)
       │
       └──► [NO MATCH]
                 │
                 ▼
          3. Check Listening Table (listening_hash)
                 │
                 ├──► [MATCH FOUND] ──► Push request to Listening Socket FD (accept() queue)
                 │
                 └──► [NO MATCH] ──► Send TCP RST (Port Closed / Connection Refused)

```
## 3. Algorithm Step-by-Step
### Phase 1: Fast Path — Established Table (ehash)
 1. **Extract** (saddr, sport, daddr, dport) from the packet.
 2. **Compute Hash:**
   
 3. **Lookup:** Jump directly to Established_Table[bucket_index].
 4. **Compare:** Iterate through the bucket's short linked list to verify an exact match on all 4 fields.
   * **If match:** Route data to the connection's dedicated socket FD. Done.
### Phase 2: Fallback Path — Listening Table (listening_hash)
*Triggered ONLY if Phase 1 returns NULL (e.g., a new client sending a SYN packet).*
 1. **Compute Hash:**
   
 2. **Lookup:** Jump to Listening_Table[listen_index].
 3. **Compare:** Match destination IP and destination port.
   * **If match:** Hand connection request to the listening socket FD (greeter/receptionist) to begin the 3-way handshake.
### Phase 3: Default — Reject / Reset
*Triggered if both Phase 1 and Phase 2 return NULL.*
 1. Drop the packet.
 2. Send a TCP RST (Reset) packet back to the sender.
## 4. Kernel Pseudocode Representation
```c
struct socket* lookup_packet(Packet *pkt) {
    // 1. Hash full 4-tuple for fast path
    u32 hash = hash_4tuple(pkt->src_ip, pkt->src_port, 
                           pkt->dst_ip, pkt->dst_port);

    // 2. Check Established Connections (Active FDs)
    struct socket *sk = search_established_table(hash, pkt);
    if (sk != NULL) {
        return sk; // FAST PATH: Route directly to active app socket
    }

    // 3. Fallback: Check Listening Sockets (Accept Queue)
    sk = search_listening_table(pkt->dst_ip, pkt->dst_port);
    if (sk != NULL) {
        return sk; // FALLBACK PATH: Route to listening socket (fd_listen)
    }

    // 4. No matching socket exists
    send_tcp_rst(pkt);
    return NULL;
}

```
## Key Takeaways
 * **Constant Time Performance (O(1)):** Hashing ensures the lookup takes less than a microsecond regardless of whether the system has 1 connection or 100,000 connections active.
 * **Disambiguation:** Traffic for Discord, Google, and your custom HTTP server can run on the exact same network card simultaneously without cross-talk because their 4-tuples yield distinct hash entries.
 * **Established Priority:** Ongoing data transfers bypass listening sockets entirely because the kernel evaluates the Established Table first.

Here is a clean, structured Markdown file summarizing our discussion. You can copy and save this directly into a .md file for your repository.
```markdown
# C Socket Syntax & Pointer Casting Explained

## TL;DR
When you write:
```c
bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

```
You are taking the raw memory address of your IPv4 structure (&serv_addr) and force-casting that address to a generic pointer type (struct sockaddr *).
**The data in RAM does not change.** You are telling the compiler and function to look at the exact same memory location through a different structural "lens."
## 1. Deconstructing (struct sockaddr *)&serv_addr
```text
(struct sockaddr *) &serv_addr
 \_______________/  \________/
         │               │
         │               └─ 1. Get memory address (e.g., 0x7ffeefbff4a0)
         └───────────────── 2. Force-cast pointer to generic struct pointer type

```
 * **&serv_addr**: Evaluates to a memory address pointing to a struct sockaddr_in (IPv4).
 * **(struct sockaddr *)**: Tells C to treat that raw memory address as if it points to a generic struct sockaddr.
## 2. Why does C force this syntax? (Fake OOP)
Modern languages have class inheritance (e.g., IPv4Address inherits from BaseAddress). C does **not** have inheritance.
When the BSD Sockets API was created in the early 1980s, functions like bind(), connect(), and accept() needed to accept multiple network protocols (IPv4, IPv6, Unix Sockets, etc.).
Instead of writing separate functions like bind_ipv4() and bind_ipv6(), the designers built a **generic "base" struct**:
```c
// Generic struct expected by socket functions
struct sockaddr {
    unsigned short sa_family; // Address family (e.g., AF_INET, AF_INET6)
    char           sa_data[14]; // Protocol-specific bytes
};

```
## 3. The Memory Alignment & Tagging Trick
This trick works safely because all socket structs are engineered to put the **address family identifier** (AF_INET, AF_INET6, etc.) at the very beginning (offset 0) of the struct memory layout:
```text
Memory Address:   0x00                     0x02                                        0x10
                ┌────────────────────────┬──────────────────────────────────────────────┐
Generic View:   │ sa_family (2 bytes)    │ sa_data (14 bytes)                           │
                ├────────────────────────┼─────────────┬──────────────┬─────────────────┤
IPv4 View:      │ sin_family (2 bytes)   │ sin_port    │ sin_addr     │ padding         │
                └────────────────────────┴─────────────┴──────────────┴─────────────────┘

```
### How bind() processes this inside OS code:
 1. **Reads location & size:** Accepts the raw address and sizeof(serv_addr) safety boundary.
 2. **Peeks at the tag:** Reads the first 2 bytes (sa_family).
 3. **Identifies type:** If the first 2 bytes equal AF_INET, bind() knows the buffer is actually an IPv4 struct (struct sockaddr_in).
 4. **Parses payload:** Casts the pointer back internally to read the port and IP address correctly.
## 4. Why wasn't void * used instead?
A **void *** (void pointer) is C's standard generic pointer:
 * It holds any memory address without a type.
 * It requires no explicit casting ((type *)).
 * It cannot be dereferenced or used in pointer arithmetic directly.
**Why bind() doesn't use void *:**
BSD Sockets were created **before** generic void * pointers were standardized in C (which happened in ANSI C / C89). The API used explicit structure pointer casting as manual object orientation, and that legacy signature remains frozen in POSIX standards today for backward compatibility.
## Cheat Sheet Mental Model
 * **Memory Address:** Just a number pointing to RAM (e.g., 0x7ffeefbff4a0).
 * **Pointer Casting:** Changing the instructions on *how* to read bytes at that address, without moving or altering a single bit in RAM.

