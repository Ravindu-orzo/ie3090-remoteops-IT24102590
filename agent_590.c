#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <semaphore.h>

/*
 * [Lecture 03: well-known server port]
 * The server listens on a fixed, well-known port so clients know
 * where to connect. A socket address = IP address + port number. The
 * controller uses the same number (SERVER_PORT in controller_590.c).
 */
#define PORT 9410
#define SID "0952"
#define AUTH_TOKEN "OPS-2590"

/*
 * [Lecture 03 / Lecture 05: backlog and limiting connections]
 * Used in two ways: as the listen() backlog (the length of the queue
 * of waiting connections; 5 is the historical value) and as the cap
 * on simultaneous clients (see client_slots in main). Lecture 05
 * lists limiting the number of connections as a defence against
 * denial-of-service.
 */
#define MAX_CLIENTS 5
#define MAX_LINE 8192
#define MAX_FILE_SIZE (10 * 1024 * 1024)

#define STORAGE_DIR "./agentfiles/IT24102590"
#define LOG_FILE "remoteops_IT24102590.log"

static sem_t client_slots;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *log_file = NULL;

/* -------------------- LOGGING -------------------- */

void log_event(const char *format, ...)
{
    pthread_mutex_lock(&log_mutex);

    if (log_file != NULL) {
        time_t now = time(NULL);
        struct tm tm_now;

        localtime_r(&now, &tm_now);

        fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d] ",
                tm_now.tm_year + 1900,
                tm_now.tm_mon + 1,
                tm_now.tm_mday,
                tm_now.tm_hour,
                tm_now.tm_min,
                tm_now.tm_sec);

        va_list args;
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);

        fprintf(log_file, "\n");
        fflush(log_file);
    }

    pthread_mutex_unlock(&log_mutex);
}

/* -------------------- SEND ALL -------------------- */

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
        ssize_t n = send(fd, buffer + sent, length - sent, 0);

        if (n <= 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        sent += (size_t)n;
    }

    return 0;
}

/* -------------------- SEND LINE -------------------- */

/*
 * [Lecture 02: byte stream needs its own message boundary]
 * TCP does not keep message boundaries, so every reply ends with a
 * newline. This helper formats the text, adds the '\n' if it is
 * missing and sends the whole line with send_all().
 */
int send_line(int fd, const char *format, ...)
{
    char buffer[MAX_LINE];

    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    size_t len = strlen(buffer);

    if (len == 0 || buffer[len - 1] != '\n') {
        if (len + 1 >= sizeof(buffer))
            return -1;

        buffer[len] = '\n';
        buffer[len + 1] = '\0';
        len++;
    }

    return send_all(fd, buffer, len);
}

/* -------------------- RECEIVE ONE LINE -------------------- */

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

        if (c != '\r') {
            buffer[pos++] = c;
        }
    }

    buffer[pos] = '\0';

    return 1;
}

/* -------------------- RECEIVE EXACT BYTES -------------------- */

/*
 * [Lecture 02: readn()]
 * Keeps calling recv() until EXACTLY 'length' bytes have arrived,
 * because one recv() may return fewer bytes than requested. EOF (n
 * == 0) is treated as a failure here, unlike the lecture's readn()
 * which returns the partial count.
 */
int recv_exact(int fd, void *data, size_t length)
{
    size_t received = 0;
    char *buffer = (char *)data;

    while (received < length) {
        ssize_t n = recv(fd, buffer + received,
                         length - received, 0);

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

/* -------------------- FILENAME VALIDATION -------------------- */

int valid_filename(const char *filename)
{
    size_t len = strlen(filename);

    if (len == 0 || len > 100)
        return 0;

    if (strstr(filename, "..") != NULL)
        return 0;

    if (strchr(filename, '/') != NULL)
        return 0;

    if (strchr(filename, '\\') != NULL)
        return 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)filename[i];

        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return 0;
    }

    return 1;
}

/* -------------------- SYSTEM INFORMATION -------------------- */

void get_sysinfo(char *output, size_t size)
{
    double load = 0.0;
    double uptime = 0.0;

    unsigned long long mem_total = 0;
    unsigned long long mem_available = 0;

    FILE *fp;

    if (getloadavg(&load, 1) != 1)
        load = 0.0;

    fp = fopen("/proc/uptime", "r");

    if (fp != NULL) {
        fscanf(fp, "%lf", &uptime);
        fclose(fp);
    }

    fp = fopen("/proc/meminfo", "r");

    if (fp != NULL) {
        char line[256];

        while (fgets(line, sizeof(line), fp)) {

            if (sscanf(line, "MemTotal: %llu kB",
                       &mem_total) == 1) {
                continue;
            }

            if (sscanf(line, "MemAvailable: %llu kB",
                       &mem_available) == 1) {
                continue;
            }
        }

        fclose(fp);
    }

    double memory_used = 0.0;

    if (mem_total > 0) {
        memory_used =
            ((double)(mem_total - mem_available) /
             (double)mem_total) * 100.0;
    }

    snprintf(output, size,
             "CPU_LOAD=%.2f MEM_USED=%.1f%% UPTIME=%.0f_SECONDS",
             load,
             memory_used,
             uptime);
}

/* -------------------- SYSINFO COMMAND -------------------- */

void handle_sysinfo(int fd)
{
    char info[512];

    get_sysinfo(info, sizeof(info));

    send_line(fd,
              "OK SYSINFO %s SID:%s",
              info,
              SID);
}

/* -------------------- LIST PROCESS -------------------- */

void handle_listproc(int fd)
{
    FILE *fp = popen("ps -e -o pid=,comm=", "r");

    if (fp == NULL) {
        send_line(fd,
                  "ERR 003 PROCESS_LIST_FAILED SID:%s",
                  SID);
        return;
    }

    char result[7000];
    char line[256];

    result[0] = '\0';

    while (fgets(line, sizeof(line), fp)) {

        line[strcspn(line, "\r\n")] = '\0';

        if (strlen(result) + strlen(line) + 2
            < sizeof(result)) {

            strcat(result, line);
            strcat(result, " ; ");
        }
    }

    pclose(fp);

    send_line(fd,
              "OK PROCS %sSID:%s",
              result,
              SID);
}

/* -------------------- EXEC WHITELIST -------------------- */

void handle_exec(int fd, const char *command)
{
    const char *shell_command = NULL;

    if (strcmp(command, "DATE") == 0) {
        shell_command = "date";
    }
    else if (strcmp(command, "UPTIME") == 0) {
        shell_command = "uptime";
    }
    else if (strcmp(command, "DISKFREE") == 0) {
        shell_command = "df -h .";
    }
    else if (strcmp(command, "HOSTNAME") == 0) {
        shell_command = "hostname";
    }
    else if (strcmp(command, "WHOAMI") == 0) {
        shell_command = "whoami";
    }
    else {
        log_event("Rejected EXEC command: %s", command);

        send_line(fd,
                  "ERR 002 COMMAND_NOT_ALLOWED SID:%s",
                  SID);

        return;
    }

    FILE *fp = popen(shell_command, "r");

    if (fp == NULL) {
        send_line(fd,
                  "ERR 003 EXEC_FAILED SID:%s",
                  SID);
        return;
    }

    char result[3000];
    char line[512];

    result[0] = '\0';

    while (fgets(line, sizeof(line), fp)) {

        line[strcspn(line, "\r\n")] = '\0';

        if (strlen(result) + strlen(line) + 2
            < sizeof(result)) {

            strcat(result, line);
            strcat(result, " ");
        }
    }

    pclose(fp);

    send_line(fd,
              "OK EXEC_RESULT %sSID:%s",
              result,
              SID);
}

/* -------------------- PUT FILE -------------------- */

/*
 * [Lecture 02: receiving a file over a byte stream]
 * The controller first sends a header line ("PUT name size"), then
 * exactly 'size' bytes. Because recv() can return fewer bytes than
 * requested, we loop: 'remaining' is the number of bytes still
 * expected, each recv() reduces it, and the loop ends when it
 * reaches zero. If recv() returns 0 or -1 before that, the
 * connection died mid-transfer and the partial file is removed.
 *
 * The size and filename are validated first and buffers are bounded
 * (lecture: check return values, never allow buffer overflow).
 */
int handle_put(int fd, const char *request)
{
    char filename[101];
    long long filesize;

    if (sscanf(request,
               "PUT %100s %lld",
               filename,
               &filesize) != 2) {

        send_line(fd,
                  "ERR 003 INVALID_PUT SID:%s",
                  SID);

        return 0;
    }

    if (!valid_filename(filename)) {

        send_line(fd,
                  "ERR 003 INVALID_FILENAME SID:%s",
                  SID);

        return 0;
    }

    if (filesize < 0 || filesize > MAX_FILE_SIZE) {

        send_line(fd,
                  "ERR 004 FILE_TOO_LARGE SID:%s",
                  SID);

        return 0;
    }

    char path[512];

    snprintf(path,
             sizeof(path),
             "%s/%s",
             STORAGE_DIR,
             filename);

    FILE *fp = fopen(path, "wb");

    if (fp == NULL) {

        send_line(fd,
                  "ERR 003 FILE_OPEN_FAILED SID:%s",
                  SID);

        return 0;
    }

    char buffer[8192];
    long long remaining = filesize;

    while (remaining > 0) {

        size_t wanted =
            remaining > (long long)sizeof(buffer)
            ? sizeof(buffer)
            : (size_t)remaining;

        ssize_t n = recv(fd, buffer, wanted, 0);

        if (n <= 0) {

            fclose(fp);
            remove(path);

            log_event("PUT failed for %s",
                      filename);

            return -1;
        }

        size_t written =
            fwrite(buffer, 1, (size_t)n, fp);

        if (written != (size_t)n) {

            fclose(fp);
            remove(path);

            send_line(fd,
                      "ERR 003 FILE_WRITE_FAILED SID:%s",
                      SID);

            return 0;
        }

        remaining -= n;
    }

    fclose(fp);

    log_event("PUT completed: %s (%lld bytes)",
              filename,
              filesize);

    send_line(fd,
              "OK FILE_RECEIVED SID:%s",
              SID);

    return 0;
}

/* -------------------- GET FILE -------------------- */

/*
 * [Lecture 02: sending a file over a byte stream]
 * Mirror image of PUT: first send a header line announcing the file
 * name and size ("OK FILE_SEND name size"), then send exactly that
 * many bytes in chunks of at most 8192, using send_all() so partial
 * sends are handled. 'remaining' tracks the bytes still to send.
 */
int handle_get(int fd, const char *request)
{
    char filename[101];

    if (sscanf(request,
               "GET %100s",
               filename) != 1) {

        send_line(fd,
                  "ERR 003 INVALID_GET SID:%s",
                  SID);

        return 0;
    }

    if (!valid_filename(filename)) {

        send_line(fd,
                  "ERR 003 INVALID_FILENAME SID:%s",
                  SID);

        return 0;
    }

    char path[512];

    snprintf(path,
             sizeof(path),
             "%s/%s",
             STORAGE_DIR,
             filename);

    struct stat st;

    if (stat(path, &st) != 0 ||
        !S_ISREG(st.st_mode)) {

        send_line(fd,
                  "ERR 005 FILE_NOT_FOUND SID:%s",
                  SID);

        log_event("GET file not found: %s",
                  filename);

        return 0;
    }

    long long filesize =
        (long long)st.st_size;

    FILE *fp = fopen(path, "rb");

    if (fp == NULL) {

        send_line(fd,
                  "ERR 003 FILE_OPEN_FAILED SID:%s",
                  SID);

        return 0;
    }

    send_line(fd,
              "OK FILE_SEND %s %lld SID:%s",
              filename,
              filesize,
              SID);

    char buffer[8192];

    long long remaining = filesize;

    while (remaining > 0) {

        size_t wanted =
            remaining > (long long)sizeof(buffer)
            ? sizeof(buffer)
            : (size_t)remaining;

        size_t n =
            fread(buffer, 1, wanted, fp);

        if (n == 0)
            break;

        if (send_all(fd, buffer, n) < 0) {

            fclose(fp);

            log_event("GET failed while sending: %s",
                      filename);

            return -1;
        }

        remaining -= (long long)n;
    }

    fclose(fp);

    if (remaining != 0) {

        log_event("GET incomplete: %s",
                  filename);

        return -1;
    }

    log_event("GET completed: %s (%lld bytes)",
              filename,
              filesize);

    return 0;
}

/* -------------------- MONITORING -------------------- */

typedef struct {
    int fd;
    char client_ip[INET_ADDRSTRLEN];

    pthread_t thread;

    pthread_mutex_t mutex;

    int running;
    int stop;

    int udp_socket;
    int udp_port;

    struct sockaddr_in udp_address;

} ClientContext;

/* UDP monitoring thread */

/*
 * [Lecture 03/02: UDP sender]
 * UDP (SOCK_DGRAM) is connectionless and unreliable: no handshake,
 * no listen/accept/connect, and packets may be lost. That suits
 * periodic status readings, since a lost one is replaced 2 seconds
 * later. This thread sends one SYSINFO datagram roughly every 2
 * seconds until 'stop' is set.
 */
void *monitor_thread(void *arg)
{
    ClientContext *ctx =
        (ClientContext *)arg;

    while (1) {

        pthread_mutex_lock(&ctx->mutex);

        int stop = ctx->stop;
        int udp_fd = ctx->udp_socket;

        pthread_mutex_unlock(&ctx->mutex);

        if (stop)
            break;

        char info[512];

        get_sysinfo(info, sizeof(info));

        char packet[700];

        snprintf(packet,
                 sizeof(packet),
                 "SYSINFO %s SID:%s",
                 info,
                 SID);

        /*
         * [Lecture 02: sendto() (process to kernel)]
         * sendto() sends one datagram to the destination address given in
         * udp_address. The address length is passed as a plain value
         * (sizeof), because this is process to kernel; the cast to struct
         * sockaddr * is the generic-address pattern. No bind() is needed for
         * the sender, the OS gives the UDP socket an ephemeral port.
         */
        sendto(udp_fd,
               packet,
               strlen(packet),
               0,
               (struct sockaddr *)&ctx->udp_address,
               sizeof(ctx->udp_address));

        /* Wait approximately 2 seconds */

        for (int i = 0; i < 20; i++) {

            usleep(100000);

            pthread_mutex_lock(&ctx->mutex);

            stop = ctx->stop;

            pthread_mutex_unlock(&ctx->mutex);

            if (stop)
                break;
        }
    }

    pthread_mutex_lock(&ctx->mutex);

    ctx->running = 0;

    pthread_mutex_unlock(&ctx->mutex);

    return NULL;
}

/* Stop monitor */

void stop_monitor(ClientContext *ctx)
{
    pthread_mutex_lock(&ctx->mutex);

    if (!ctx->running) {
        pthread_mutex_unlock(&ctx->mutex);
        return;
    }

    ctx->stop = 1;

    pthread_t thread =
        ctx->thread;

    pthread_mutex_unlock(&ctx->mutex);

    pthread_join(thread, NULL);

    pthread_mutex_lock(&ctx->mutex);

    if (ctx->udp_socket >= 0) {
        close(ctx->udp_socket);
        ctx->udp_socket = -1;
    }

    ctx->running = 0;
    ctx->stop = 0;

    pthread_mutex_unlock(&ctx->mutex);

    log_event("MONITOR STOP for %s",
              ctx->client_ip);
}

/* Start monitor */

int start_monitor(ClientContext *ctx,
                  int udp_port)
{
    stop_monitor(ctx);

    int udp_fd =
        socket(AF_INET,
               SOCK_DGRAM,
               0);

    if (udp_fd < 0)
        return -1;

    memset(&ctx->udp_address,
           0,
           sizeof(ctx->udp_address));

    ctx->udp_address.sin_family =
        AF_INET;

    ctx->udp_address.sin_port =
        htons((uint16_t)udp_port);

    /*
     * [Lecture 02: inet_pton()]
     * inet_pton() converts the controller's IP address text (e.g.
     * "127.0.0.1") into the 32-bit binary form stored in sin_addr. It
     * returns 1 on success, so anything other than 1 means failure.
     * Together with memset() above and htons() on the port, this fills
     * the sockaddr_in destination used by sendto().
     */
    if (inet_pton(AF_INET,
                  ctx->client_ip,
                  &ctx->udp_address.sin_addr) != 1) {

        close(udp_fd);
        return -1;
    }

    pthread_mutex_lock(&ctx->mutex);

    ctx->udp_socket = udp_fd;
    ctx->udp_port = udp_port;
    ctx->stop = 0;
    ctx->running = 1;

    pthread_mutex_unlock(&ctx->mutex);

    if (pthread_create(&ctx->thread,
                       NULL,
                       monitor_thread,
                       ctx) != 0) {

        pthread_mutex_lock(&ctx->mutex);

        ctx->running = 0;

        close(ctx->udp_socket);
        ctx->udp_socket = -1;

        pthread_mutex_unlock(&ctx->mutex);

        return -1;
    }

    log_event("MONITOR START for %s UDP port %d",
              ctx->client_ip,
              udp_port);

    return 0;
}

/* -------------------- CLIENT THREAD -------------------- */

/*
 * [Lecture 04: the per-client worker (thread version of the fork child)]
 * Concurrent server idea: the main loop only accepts connections and
 * hands each one to a worker, then goes straight back to accept().
 * The lecture does this with fork(); this agent uses one THREAD per
 * client. This function is the worker: it serves one connected
 * socket until the client leaves.
 *
 * Because each client has its own thread, a slow or silent client
 * blocks only its own thread (lecture 05: one defence against
 * denial-of-service).
 */
void *client_handler(void *arg)
{
    ClientContext *ctx =
        (ClientContext *)arg;

    int fd = ctx->fd;

    char line[MAX_LINE];

    int authenticated = 0;

    log_event("Client connected: %s",
              ctx->client_ip);

    while (1) {

        /*
         * [Lecture 04: detecting that the client left (EOF)]
         * Like str_echo() in the lecture's echo server: read a line, act on
         * it, repeat. recv_line() returns 0 when the client closed the
         * connection (FIN received) and -1 on error, so 'result <= 0' ends
         * the loop and the cleanup below runs.
         */
        int result =
            recv_line(fd,
                      line,
                      sizeof(line));

        if (result <= 0)
            break;

        log_event("Command from %s: %s",
                  ctx->client_ip,
                  line);

        /* ---------- AUTHENTICATION ---------- */

        if (!authenticated) {

            if (strncmp(line,
                         "AUTH ",
                         5) == 0) {

                const char *token =
                    line + 5;

                if (strcmp(token,
                           AUTH_TOKEN) == 0) {

                    authenticated = 1;

                    log_event("AUTH success from %s",
                              ctx->client_ip);

                    send_line(fd,
                              "OK AUTHENTICATED SID:%s",
                              SID);
                }
                else {

                    log_event("AUTH failed from %s",
                              ctx->client_ip);

                    send_line(fd,
                              "ERR 001 AUTH_FAILED SID:%s",
                              SID);
                }

                continue;
            }

            send_line(fd,
                      "ERR 001 AUTH_REQUIRED SID:%s",
                      SID);

            continue;
        }

        /* ---------- SYSINFO ---------- */

        if (strcmp(line,
                   "SYSINFO") == 0) {

            handle_sysinfo(fd);
        }

        /* ---------- LISTPROC ---------- */

        else if (strcmp(line,
                        "LISTPROC") == 0) {

            handle_listproc(fd);
        }

        /* ---------- EXEC ---------- */

        else if (strncmp(line,
                         "EXEC ",
                         5) == 0) {

            handle_exec(fd,
                        line + 5);
        }

        /* ---------- PUT ---------- */

        else if (strncmp(line,
                         "PUT ",
                         4) == 0) {

            if (handle_put(fd, line) < 0)
                break;
        }

        /* ---------- GET ---------- */

        else if (strncmp(line,
                         "GET ",
                         4) == 0) {

            if (handle_get(fd, line) < 0)
                break;
        }

        /* ---------- MONITOR START ---------- */

        else if (strncmp(line,
                         "MONITOR START ",
                         14) == 0) {

            int udp_port =
                atoi(line + 14);

            if (udp_port < 1 ||
                udp_port > 65535) {

                send_line(fd,
                          "ERR 003 INVALID_UDP_PORT SID:%s",
                          SID);

                continue;
            }

            if (start_monitor(ctx,
                              udp_port) == 0) {

                send_line(fd,
                          "OK MONITOR_STARTED SID:%s",
                          SID);
            }
            else {

                send_line(fd,
                          "ERR 003 MONITOR_FAILED SID:%s",
                          SID);
            }
        }

        /* ---------- MONITOR STOP ---------- */

        else if (strcmp(line,
                        "MONITOR STOP") == 0) {

            stop_monitor(ctx);

            send_line(fd,
                      "OK MONITOR_STOPPED SID:%s",
                      SID);
        }

        /* ---------- QUIT ---------- */

        else if (strcmp(line,
                        "QUIT") == 0) {

            stop_monitor(ctx);

            send_line(fd,
                      "OK BYE SID:%s",
                      SID);

            log_event("Client graceful disconnect: %s",
                      ctx->client_ip);

            break;
        }

        /* ---------- UNKNOWN ---------- */

        else {

            send_line(fd,
                      "ERR 006 UNKNOWN_COMMAND SID:%s",
                      SID);
        }
    }

    stop_monitor(ctx);

    /*
     * [Lecture 04: closing the connected socket]
     * Cleanup for this client. close(fd) lowers the descriptor's
     * reference count and, at 0, the real close happens and TCP's FIN
     * sequence starts. Every connected socket returned by accept() must
     * be closed, otherwise the server eventually runs out of
     * descriptors.
     *
     * sem_post() frees this client's slot so another client may be
     * served.
     */
    log_event("Client disconnected: %s",
              ctx->client_ip);

    close(fd);

    pthread_mutex_destroy(&ctx->mutex);

    free(ctx);

    sem_post(&client_slots);

    return NULL;
}

/* -------------------- MAIN -------------------- */

int main(void)
{
    /*
     * [Lecture 04: signal disposition]
     * A signal is a software notification. Each signal has a
     * disposition: run a handler function, ignore it (SIG_IGN) or use
     * the default (SIG_DFL). Here the agent chooses to IGNORE SIGPIPE.
     * (SIGPIPE itself is not covered in the lectures; the lecture
     * example is SIGCHLD.) Without this, writing to a connection the
     * other side already closed could kill the whole agent; now send()
     * just returns -1, which send_all() handles.
     */
    signal(SIGPIPE, SIG_IGN);

    mkdir("agentfiles", 0755);
    mkdir(STORAGE_DIR, 0755);

    log_file =
        fopen(LOG_FILE, "a");

    if (log_file == NULL) {

        perror("Cannot open log file");

        return 1;
    }

    sem_init(&client_slots,
             0,
             MAX_CLIENTS);

    /*
     * [Lecture 03: socket()]
     * Server step 1: socket(family, type, protocol) creates the endpoint
     * and returns a socket descriptor (or -1 on failure). AF_INET =
     * IPv4, SOCK_STREAM = TCP (reliable byte stream), protocol 0 =
     * default. This is the LISTENING socket; it is only used to accept
     * new connections.
     */
    int server_fd =
        socket(AF_INET,
               SOCK_STREAM,
               0);

    if (server_fd < 0) {

        perror("socket");

        fclose(log_file);

        return 1;
    }

    int reuse = 1;

    setsockopt(server_fd,
               SOL_SOCKET,
               SO_REUSEADDR,
               &reuse,
               sizeof(reuse));

    /*
     * [Lecture 02: socket address structure and byte order]
     * sockaddr_in holds this server's own address. memset() clears the
     * whole structure (sin_zero must be 0). sin_family = AF_INET (IPv4).
     * INADDR_ANY means "accept connections on any local network
     * interface" (the lecture writes htonl(INADDR_ANY); here htonl is
     * omitted, which is fine because INADDR_ANY is 0 and 0 is the same
     * in both byte orders). htons(PORT) converts the port to network
     * byte order (big-endian).
     */
    struct sockaddr_in server_address;

    memset(&server_address,
           0,
           sizeof(server_address));

    server_address.sin_family =
        AF_INET;

    server_address.sin_addr.s_addr =
        INADDR_ANY;

    server_address.sin_port =
        htons(PORT);

    /*
     * [Lecture 03: bind()]
     * Server step 2: bind() assigns the local address (IP + port) to the
     * socket. A new socket has no port, and a server needs its fixed
     * well-known one. Arguments: the socket, a pointer to the address
     * cast to the generic struct sockaddr * (all socket functions take
     * that type), and the structure size. Returns 0 on success, -1 on
     * failure.
     */
    if (bind(server_fd,
             (struct sockaddr *)&server_address,
             sizeof(server_address)) < 0) {

        perror("bind");

        close(server_fd);
        fclose(log_file);

        return 1;
    }

    /*
     * [Lecture 03: listen()]
     * Server step 3: listen() marks the socket as passive, i.e. ready to
     * accept incoming connections. The second argument is the backlog,
     * the length of the queue of waiting connections the kernel keeps
     * (MAX_CLIENTS = 5, the historical value).
     */
    if (listen(server_fd,
               MAX_CLIENTS) < 0) {

        perror("listen");

        close(server_fd);
        fclose(log_file);

        return 1;
    }

    printf("\n");
    printf("========================================\n");
    printf("        RemoteOps Agent\n");
    printf("========================================\n");
    printf("Registration : IT24102590\n");
    printf("TCP Port     : 9410\n");
    printf("SID          : 0952\n");
    printf("Max Clients  : 5\n");
    printf("Storage      : %s\n", STORAGE_DIR);
    printf("Log File     : %s\n", LOG_FILE);
    printf("========================================\n");
    printf("Agent is listening ...\n\n");

    log_event("Agent started on TCP port %d",
              PORT);

    while (1) {

        /*
         * [Lecture 03/02: accept() and the value-result argument]
         * Server step 4 (repeated forever): accept() takes the next
         * completed connection and returns a BRAND-NEW descriptor
         * (client_fd) for that one client. The listening socket stays open
         * for the next client.
         *
         * Value-result argument: the kernel fills client_address for us, so
         * we pass a POINTER to the length. Before the call client_len holds
         * the size of our buffer (the value); after the call the kernel
         * stores how many bytes it used (the result). That is why client_len
         * is reset to sizeof(...) on every loop pass.
         */
        struct sockaddr_in client_address;
        socklen_t client_len =
            sizeof(client_address);

        int client_fd =
            accept(server_fd,
                   (struct sockaddr *)&client_address,
                   &client_len);

        /*
         * [Lecture 04: interrupted system calls (EINTR)]
         * accept() is a slow system call: it can block for a long time, and
         * if a signal arrives while it waits it may fail with errno = EINTR.
         * That is not a real error, so we simply call accept() again. Any
         * other error is printed and we keep serving.
         */
        if (client_fd < 0) {

            if (errno == EINTR)
                continue;

            perror("accept");
            continue;
        }

        /*
         * [Lecture 05: limiting the number of clients]
         * Counts a client slot: at most MAX_CLIENTS clients are served at
         * once (semaphores themselves are not in the lectures; think of it
         * as a counter of free slots). Limiting connections is one of the
         * lecture's denial-of-service defences.
         */
        sem_wait(&client_slots);

        ClientContext *ctx =
            calloc(1,
                   sizeof(ClientContext));

        if (ctx == NULL) {

            close(client_fd);
            sem_post(&client_slots);

            continue;
        }

        ctx->fd = client_fd;

        /*
         * [Lecture 02: inet_ntop()]
         * inet_ntop() converts the client's binary IPv4 address back to text
         * (e.g. "127.0.0.1") for logging. The size of the destination buffer
         * is passed so it cannot overflow; client_ip is
         * char[INET_ADDRSTRLEN] (16 bytes, enough for an IPv4 string).
         */
        inet_ntop(AF_INET,
                  &client_address.sin_addr,
                  ctx->client_ip,
                  sizeof(ctx->client_ip));

        ctx->udp_socket = -1;
        ctx->running = 0;
        ctx->stop = 0;

        pthread_mutex_init(&ctx->mutex,
                           NULL);

        pthread_t thread;

        /*
         * [Lecture 04: concurrent server, thread per client]
         * Same shape as the lecture's fork() server: the main loop (the
         * 'parent') only accepts connections, and each client gets its own
         * worker (here a thread running client_handler instead of a forked
         * child). Then the loop returns to accept() to wait for the next
         * client.
         *
         * If the thread cannot be created, the connected socket is closed
         * and the slot released, so no descriptor is leaked.
         */
        if (pthread_create(&thread,
                           NULL,
                           client_handler,
                           ctx) != 0) {

            close(client_fd);

            pthread_mutex_destroy(&ctx->mutex);

            free(ctx);

            sem_post(&client_slots);

            continue;
        }

        /*
         * [Lecture 04: cleaning up finished workers]
         * A detached thread is cleaned up automatically by the OS when it
         * ends, so main never has to wait for it. This plays the role that
         * wait()/waitpid() with SIGCHLD played in the fork version to avoid
         * zombie processes.
         */
        pthread_detach(thread);
    }

    close(server_fd);

    sem_destroy(&client_slots);

    fclose(log_file);

    return 0;
}
