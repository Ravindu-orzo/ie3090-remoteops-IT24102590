#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

/*
 * [Lecture 03: TCP client/server steps]
 * The controller is the CLIENT and the agent is the SERVER. A server
 * uses a fixed, well-known port so clients know where to connect; a
 * client does not choose a port, the OS gives it a temporary
 * (ephemeral) one automatically. A socket address = IP address +
 * port number.
 *
 * 127.0.0.1 is the loopback address, meaning "this same computer".
 * The port here must match PORT in agent_590.c.
 */
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9410

#define SID "0952"
#define AUTH_TOKEN "OPS-2590"

#define MAX_LINE 8192
#define BUFFER_SIZE 8192

static int udp_socket_fd = -1;
static volatile int udp_running = 0;
static pthread_t udp_thread;

/* ---------------- SEND ALL ---------------- */

/*
 * [Lecture 02: writen()]
 * TCP is a byte stream, and send() may transfer FEWER bytes than
 * requested (kernel buffer limits). This is not an error, so we loop
 * and send only what is left until everything is delivered. 'sent'
 * counts bytes already delivered; buffer + sent points to the next
 * unsent byte.
 *
 * If a signal interrupts the call, send() returns -1 with errno =
 * EINTR. That is not a real failure, so we just call it again. Any
 * other failure returns -1. This is the same structure as the
 * lecture's writen().
 */
int send_all(int fd, const void *data, size_t length)
{
    size_t sent = 0;
    const char *buffer = (const char *)data;

    while (sent < length) {

        ssize_t n = send(fd,
                         buffer + sent,
                         length - sent,
                         0);

        if (n <= 0) {

            if (errno == EINTR)
                continue;

            return -1;
        }

        sent += (size_t)n;
    }

    return 0;
}

/* ---------------- SEND LINE ---------------- */

/*
 * [Lecture 02: byte stream needs its own message boundary]
 * TCP does not keep message boundaries, so this program ends every
 * command with a newline. This helper adds the '\n' if it is missing
 * and then sends the whole line with send_all().
 */
int send_line(int fd, const char *line)
{
    size_t len = strlen(line);

    if (send_all(fd, line, len) < 0)
        return -1;

    if (len == 0 || line[len - 1] != '\n') {

        if (send_all(fd, "\n", 1) < 0)
            return -1;
    }

    return 0;
}

/* ---------------- RECEIVE LINE ---------------- */

/*
 * [Lecture 02: readline() Version 1]
 * Reads ONE byte per recv() call until a newline arrives (the
 * lecture's readline Version 1: simple, but one system call per
 * byte, which is fine for short command lines).
 *
 * recv() returns 0 when the other side closed the connection (EOF,
 * the FIN arrived), so we return 0 if nothing was read yet. -1 is a
 * real error, except EINTR which we retry.
 *
 * 'pos < size - 1' keeps room for the terminating '\0' and stops the
 * buffer from overflowing (lecture: make sure buffers cannot be
 * overflowed). Difference from the lecture: '\r' is skipped and the
 * '\n' is not stored.
 */
int recv_line(int fd, char *buffer, size_t size)
{
    size_t pos = 0;

    while (pos < size - 1) {

        char c;

        ssize_t n = recv(fd, &c, 1, 0);

        if (n == 0) {

            if (pos == 0)
                return 0;

            break;
        }

        if (n < 0) {

            if (errno == EINTR)
                continue;

            return -1;
        }

        if (c == '\n')
            break;

        if (c != '\r')
            buffer[pos++] = c;
    }

    buffer[pos] = '\0';

    return 1;
}

/* ---------------- RECEIVE EXACT BYTES ---------------- */

/*
 * [Lecture 02: readn()]
 * Keeps calling recv() until EXACTLY 'length' bytes have arrived,
 * because one recv() may return fewer bytes than requested. Used for
 * file downloads, where the size is known in advance.
 *
 * Difference from the lecture's readn(): EOF (n == 0) is treated as
 * a failure here, since a half-received file is useless.
 */
int recv_exact(int fd, void *data, size_t length)
{
    size_t received = 0;
    char *buffer = (char *)data;

    while (received < length) {

        ssize_t n = recv(fd,
                         buffer + received,
                         length - received,
                         0);

        if (n == 0)
            return -1;

        if (n < 0) {

            if (errno == EINTR)
                continue;

            return -1;
        }

        received += (size_t)n;
    }

    return 0;
}

/* ---------------- UDP MONITOR THREAD ---------------- */

/*
 * [Lecture 05: I/O multiplexing with select()]
 * This thread receives the UDP monitoring packets sent by the agent.
 * By default sockets use blocking I/O (recvfrom would wait forever).
 * select() waits on a set of descriptors and returns when one is
 * ready OR when the timeout expires, so the loop can regularly re-
 * check 'udp_running' and stop quickly when MONITOR STOP is used.
 */
void *udp_listener(void *arg)
{
    (void)arg;

    char buffer[1024];

    while (udp_running) {

        /*
         * [Lecture 05: fd_set macros and the timeout]
         * fd_set is a set of descriptors. FD_ZERO empties the set and FD_SET
         * adds our UDP socket to it. select() modifies both the set and the
         * timeout, so they are declared and rebuilt inside the loop on every
         * pass.
         *
         * select(maxfd1, readset, writeset, exceptset, timeout): maxfd1 =
         * highest descriptor + 1, and the timeout of 1 second means "wait up
         * to 1 second". It returns the number of ready descriptors, 0 on
         * timeout, or -1 on error, so 'result <= 0' means nothing to read
         * this round.
         */
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(udp_socket_fd, &readfds);

        struct timeval timeout;

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int result =
            select(udp_socket_fd + 1,
                   &readfds,
                   NULL,
                   NULL,
                   &timeout);

        if (result <= 0)
            continue;

        /*
         * [Lecture 05 / Lecture 02: FD_ISSET and recvfrom()]
         * FD_ISSET tests whether our socket is ready (readable). Only then
         * do we call recvfrom(), so it will not block.
         *
         * recvfrom() is a value-result call (kernel to process). The two
         * NULL arguments mean we do not care who sent the packet.
         */
        if (FD_ISSET(udp_socket_fd, &readfds)) {

            ssize_t n =
                recvfrom(udp_socket_fd,
                         buffer,
                         sizeof(buffer) - 1,
                         0,
                         NULL,
                         NULL);

            if (n > 0) {

                buffer[n] = '\0';

                printf("\n[UDP MONITOR] %s\n",
                       buffer);

                printf("Enter command: ");
                fflush(stdout);
            }
        }
    }

    return NULL;
}

/* ---------------- PUT FILE ---------------- */

/*
 * [Lecture 02: sending a file over a byte stream]
 * Because reads and writes can be partial, the file is sent in two
 * steps: first a header line announcing the file size ("PUT name
 * size"), then exactly that many bytes. 'remaining' tracks how many
 * bytes are still to send, and each chunk (at most BUFFER_SIZE) goes
 * out through send_all().
 */
void put_file(int sock)
{
    char filename[256];

    printf("Enter local filename: ");
    fflush(stdout);

    if (scanf("%255s", filename) != 1)
        return;

    FILE *fp = fopen(filename, "rb");

    if (fp == NULL) {

        perror("Cannot open local file");
        return;
    }

    fseek(fp, 0, SEEK_END);

    long long filesize =
        (long long)ftell(fp);

    fseek(fp, 0, SEEK_SET);

    printf("File size: %lld bytes\n",
           filesize);

    char command[512];

    snprintf(command,
             sizeof(command),
             "PUT %s %lld\n",
             filename,
             filesize);

    if (send_all(sock,
                 command,
                 strlen(command)) < 0) {

        fclose(fp);
        return;
    }

    char buffer[BUFFER_SIZE];

    long long remaining = filesize;

    while (remaining > 0) {

        size_t wanted =
            remaining > BUFFER_SIZE
            ? BUFFER_SIZE
            : (size_t)remaining;

        size_t n =
            fread(buffer, 1, wanted, fp);

        if (n == 0)
            break;

        if (send_all(sock,
                     buffer,
                     n) < 0) {

            fclose(fp);
            return;
        }

        remaining -= (long long)n;
    }

    fclose(fp);

    char response[MAX_LINE];

    if (recv_line(sock,
                  response,
                  sizeof(response)) > 0) {

        printf("Server: %s\n",
               response);
    }
}

/* ---------------- GET FILE ---------------- */

/*
 * [Lecture 02: receiving a file over a byte stream]
 * The agent first replies with a header line ("OK FILE_SEND name
 * size"). We read the size from it, then loop receiving exactly that
 * many bytes with recv_exact(), in chunks of at most BUFFER_SIZE,
 * until 'remaining' reaches zero.
 */
void get_file(int sock)
{
    char filename[256];

    printf("Enter remote filename: ");
    fflush(stdout);

    if (scanf("%255s", filename) != 1)
        return;

    char command[512];

    snprintf(command,
             sizeof(command),
             "GET %s\n",
             filename);

    if (send_all(sock,
                 command,
                 strlen(command)) < 0)
        return;

    char response[MAX_LINE];

    if (recv_line(sock,
                  response,
                  sizeof(response)) <= 0)
        return;

    printf("Server: %s\n",
           response);

    long long filesize;

    char received_name[256];

    if (sscanf(response,
               "OK FILE_SEND %255s %lld SID:%*s",
               received_name,
               &filesize) != 2) {

        return;
    }

    char output_name[512];

    snprintf(output_name,
             sizeof(output_name),
             "received_%s",
             received_name);

    FILE *fp =
        fopen(output_name, "wb");

    if (fp == NULL) {

        perror("Cannot create received file");
        return;
    }

    char buffer[BUFFER_SIZE];

    long long remaining = filesize;

    while (remaining > 0) {

        size_t wanted =
            remaining > BUFFER_SIZE
            ? BUFFER_SIZE
            : (size_t)remaining;

        if (recv_exact(sock,
                       buffer,
                       wanted) < 0) {

            fclose(fp);
            return;
        }

        fwrite(buffer,
               1,
               wanted,
               fp);

        remaining -= (long long)wanted;
    }

    fclose(fp);

    printf("Downloaded successfully: %s\n",
           output_name);
}

/* ---------------- CONNECT ---------------- */

/*
 * [Lecture 03: client steps (socket, then connect)]
 * Client steps: 1) socket() creates the TCP endpoint, 2) connect()
 * starts the three-way handshake (SYN, SYN-ACK, ACK) with the
 * server. Note there is no bind() here: a client does not need one,
 * the OS picks an ephemeral port.
 */
int connect_server(void)
{
    int sock =
        socket(AF_INET,
               SOCK_STREAM,
               0);

    if (sock < 0) {

        perror("socket");
        return -1;
    }

    /*
     * [Lecture 02: socket address structure, byte order, address conversion]
     * struct sockaddr_in holds the server's address: sin_family (AF_INET
     * = IPv4), sin_port and sin_addr. memset() clears the WHOLE
     * structure first (sin_zero must be 0).
     *
     * Ports must be in network byte order (big-endian, as the Internet
     * uses), so htons() converts the port from host order. inet_pton()
     * converts the text "127.0.0.1" into the 32-bit binary address and
     * stores it in sin_addr (p = presentation, n = numeric).
     */
    struct sockaddr_in server;

    memset(&server,
           0,
           sizeof(server));

    server.sin_family =
        AF_INET;

    server.sin_port =
        htons(SERVER_PORT);

    inet_pton(AF_INET,
              SERVER_IP,
              &server.sin_addr);

    /*
     * [Lecture 03/04: connect() and its failure rule]
     * connect() takes the socket, a pointer to the server address (cast
     * to the generic struct sockaddr *, which all socket functions
     * expect) and the structure length (a plain value, process to
     * kernel). It returns 0 on success, -1 on failure.
     *
     * After a failed connect() the same socket cannot be reused (lecture
     * 04), so we close it and return -1; a retry must create a new
     * socket.
     */
    if (connect(sock,
                (struct sockaddr *)&server,
                sizeof(server)) < 0) {

        perror("connect");

        close(sock);

        return -1;
    }

    return sock;
}

/* ---------------- BAD AUTH TEST ---------------- */

/*
 * [Lecture 03: full client life cycle]
 * A minimal client: connect, send one line, read one reply, close().
 * close() lowers the descriptor's reference count and, when it
 * reaches 0, TCP starts its FIN termination sequence.
 */
void bad_auth_test(void)
{
    int sock = connect_server();

    if (sock < 0)
        return;

    send_line(sock,
              "AUTH WRONG-TOKEN");

    char response[MAX_LINE];

    if (recv_line(sock,
                  response,
                  sizeof(response)) > 0) {

        printf("Server: %s\n",
               response);
    }

    close(sock);
}

/* ---------------- MAIN ---------------- */

int main(int argc, char *argv[])
{
    if (argc > 1 &&
        strcmp(argv[1], "bad") == 0) {

        printf("Testing incorrect authentication...\n");

        bad_auth_test();

        return 0;
    }

    int sock = connect_server();

    if (sock < 0)
        return 1;

    printf("\n====================================\n");
    printf("       RemoteOps Controller\n");
    printf("====================================\n");
    printf("Server : %s\n", SERVER_IP);
    printf("Port   : %d\n", SERVER_PORT);
    printf("SID    : %s\n", SID);
    printf("====================================\n");

    /*
     * [Lecture 03: TCP client communication flow]
     * After connect() the client talks to the server with send/recv:
     * write a request, read the response, repeat, and finally close().
     * The first request here is the AUTH line; every later command is
     * only accepted by the agent after it succeeds.
     */
    /* AUTH */

    send_line(sock,
              "AUTH " AUTH_TOKEN);

    char response[MAX_LINE];

    if (recv_line(sock,
                  response,
                  sizeof(response)) <= 0) {

        printf("Authentication response not received.\n");

        close(sock);

        return 1;
    }

    printf("Server: %s\n",
           response);

    if (strncmp(response,
                "OK AUTHENTICATED",
                16) != 0) {

        printf("Authentication failed.\n");

        close(sock);

        return 1;
    }

    while (1) {

        printf("\n");
        printf("========== RemoteOps ==========\n");
        printf("1. SYSINFO\n");
        printf("2. LISTPROC\n");
        printf("3. EXEC command\n");
        printf("4. PUT file\n");
        printf("5. GET file\n");
        printf("6. MONITOR START\n");
        printf("7. MONITOR STOP\n");
        printf("8. QUIT\n");
        printf("===============================\n");

        printf("Enter command: ");
        fflush(stdout);

        int choice;

        /*
         * [Lecture 05: blocking I/O and stop-and-wait]
         * The menu uses ordinary blocking calls and works in stop-and-wait
         * mode: send ONE request, then wait for ONE reply before doing
         * anything else. Simple, but the program cannot react to anything
         * else (e.g. the server closing) while it waits.
         */
        if (scanf("%d", &choice) != 1)
            break;

        if (choice == 1) {

            send_line(sock,
                      "SYSINFO");

            if (recv_line(sock,
                          response,
                          sizeof(response)) > 0) {

                printf("Server: %s\n",
                       response);
            }
        }

        else if (choice == 2) {

            send_line(sock,
                      "LISTPROC");

            if (recv_line(sock,
                          response,
                          sizeof(response)) > 0) {

                printf("Server:\n%s\n",
                       response);
            }
        }

        else if (choice == 3) {

            char command[256];

            printf("Enter EXEC command ");
            printf("(DATE/UPTIME/DISKFREE/HOSTNAME/WHOAMI): ");

            scanf("%255s", command);

            char request[512];

            snprintf(request,
                     sizeof(request),
                     "EXEC %s",
                     command);

            send_line(sock,
                      request);

            if (recv_line(sock,
                          response,
                          sizeof(response)) > 0) {

                printf("Server: %s\n",
                       response);
            }
        }

        else if (choice == 4) {

            put_file(sock);
        }

        else if (choice == 5) {

            get_file(sock);
        }

        /*
         * [Lecture 03/02: UDP receiver]
         * MONITOR START: UDP (SOCK_DGRAM) is connectionless and unreliable
         * (no handshake, no listen/accept/connect), which suits periodic
         * status readings because a lost one is replaced 2 seconds later.
         *
         * The receiver must bind() to a port so the sender knows where to
         * send. We therefore create and bind the UDP socket FIRST, start the
         * udp_listener thread, and only then tell the agent over TCP to
         * start sending.
         */
        else if (choice == 6) {

            int port;

            printf("Enter UDP port (example 9000): ");

            scanf("%d", &port);

            if (port < 1 ||
                port > 65535) {

                printf("Invalid UDP port.\n");
                continue;
            }

            udp_socket_fd =
                socket(AF_INET,
                       SOCK_DGRAM,
                       0);

            if (udp_socket_fd < 0) {

                perror("UDP socket");
                continue;
            }

            struct sockaddr_in local;

            memset(&local,
                   0,
                   sizeof(local));

            local.sin_family =
                AF_INET;

            local.sin_addr.s_addr =
                INADDR_ANY;

            local.sin_port =
                htons(port);

            /*
             * [Lecture 03/02: bind() for the UDP socket]
             * bind() assigns a local address to the socket: INADDR_ANY means
             * "any local network interface", htons(port) is the port in network
             * byte order, and the cast to struct sockaddr * plus sizeof() is the
             * usual generic-address pattern. Returns 0 on success, -1 on
             * failure.
             */
            if (bind(udp_socket_fd,
                     (struct sockaddr *)&local,
                     sizeof(local)) < 0) {

                perror("UDP bind");

                close(udp_socket_fd);
                udp_socket_fd = -1;

                continue;
            }

            udp_running = 1;

            if (pthread_create(&udp_thread,
                               NULL,
                               udp_listener,
                               NULL) != 0) {

                printf("Could not create UDP listener.\n");

                udp_running = 0;

                close(udp_socket_fd);
                udp_socket_fd = -1;

                continue;
            }

            char request[256];

            snprintf(request,
                     sizeof(request),
                     "MONITOR START %d",
                     port);

            send_line(sock,
                      request);

            if (recv_line(sock,
                          response,
                          sizeof(response)) > 0) {

                printf("Server: %s\n",
                       response);
            }
        }

        else if (choice == 7) {

            send_line(sock,
                      "MONITOR STOP");

            if (recv_line(sock,
                          response,
                          sizeof(response)) > 0) {

                printf("Server: %s\n",
                       response);
            }

            if (udp_running) {

                udp_running = 0;

                pthread_join(udp_thread,
                             NULL);

                close(udp_socket_fd);

                udp_socket_fd = -1;
            }
        }

        /*
         * [Lecture 04: closing the connection]
         * Graceful exit: send QUIT, read "OK BYE", leave the loop, and
         * close(sock) at the end of main. When the agent sees the close, its
         * recv() returns 0 (EOF) and its handler ends.
         */
        else if (choice == 8) {

            send_line(sock,
                      "QUIT");

            if (recv_line(sock,
                          response,
                          sizeof(response)) > 0) {

                printf("Server: %s\n",
                       response);
            }

            break;
        }

        else {

            printf("Invalid option.\n");
        }
    }

    if (udp_running) {

        udp_running = 0;

        pthread_join(udp_thread,
                     NULL);

        close(udp_socket_fd);
    }

    close(sock);

    printf("\nController closed.\n");

    return 0;
}
