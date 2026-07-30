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
