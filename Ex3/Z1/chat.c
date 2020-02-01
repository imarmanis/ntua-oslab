#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <stdint.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#define BUF_SIZE 512

void use_error(char *fname)
{
    fprintf(stderr, "Usage: %s [-s port | -c hostname port]\n", fname);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sd, port;
    ssize_t cnt;
    char rbuf[BUF_SIZE];
    char wbuf[BUF_SIZE];
    int rbuf_pos = 0, wbuf_pos = 0, rbuf_lim = 0, wbuf_lim = 0;
    struct sockaddr_in sa;

    if (argc < 2) use_error(argv[0]);

    signal(SIGPIPE, SIG_IGN);

    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }
    fprintf(stderr, "Created TCP socket\n");

    if (!strcmp(argv[1], "-s")) {
        char addrstr[INET_ADDRSTRLEN];
        socklen_t len;

        if (argc != 3) use_error(argv[0]);
        port = atoi(argv[2]);

        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("bind");
            exit(1);
        }
        fprintf(stderr, "Bound TCP socket to port %d\n", port);

        if (listen(sd, 1) < 0) {
            perror("listen");
            exit(1);
        }
        fprintf(stderr, "Waiting for an incoming connection...\n");

        len = sizeof(struct sockaddr_in);
        if ((sd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
            perror("accept");
            exit(1);
        }
        if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
            perror("could not format IP address");
            exit(1);
        }
        fprintf(stderr, "Incoming connection from %s:%d\n",
                addrstr, ntohs(sa.sin_port));

    } else if (!strcmp(argv[1], "-c")) {
        char *hostname;
        struct hostent *hp;

        if (argc != 4) use_error(argv[0]);
        hostname = argv[2];
        port = atoi(argv[3]);

        if ( !(hp = gethostbyname(hostname))) {
            printf("DNS lookup failed for host %s\n", hostname);
            exit(1);
        }
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
        fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
        if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
            perror("connect");
            exit(1);
        }
        fprintf(stderr, "Connected.\n");

    } else use_error(argv[0]);


    fprintf(stderr, "Chat ready.\n");

    fd_set readfds, writefds;
    for (;;) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        if (wbuf_pos < wbuf_lim) FD_SET(sd, &writefds);
        if (rbuf_lim < BUF_SIZE) FD_SET(sd, &readfds);

        if (wbuf_lim < BUF_SIZE) FD_SET(0, &readfds);
        if (rbuf_pos < rbuf_lim) FD_SET(1, &writefds);

        if (select(sd + 1, &readfds, &writefds, NULL, NULL) < 0){
            perror("select");
            exit(1);
        }

        if (FD_ISSET(sd, &writefds)) {
            if ((cnt = write(sd, wbuf + wbuf_pos, wbuf_lim - wbuf_pos)) < 0) {
                perror("write");
                exit(1);
            }
            wbuf_pos += cnt;
            if (wbuf_pos == wbuf_lim)
                wbuf_pos = wbuf_lim = 0;
        }

        if (FD_ISSET(sd, &readfds)) {
            if ((cnt = read(sd, rbuf + rbuf_lim, BUF_SIZE - rbuf_lim)) < 0) {
                perror("read");
                exit(1);
            }
            if (cnt == 0) {
                fprintf(stderr, "Peer went away\n");
                exit(1);
            }
            rbuf_lim += cnt;
        }

        if (FD_ISSET(0, &readfds)) {
            if ((cnt = read(0, wbuf + wbuf_lim, BUF_SIZE - wbuf_lim)) < 0) {
                perror("read");
                exit(1);
            }
            if (cnt == 0) {
                fprintf(stderr, "Stdin closed ?!\n");
                exit(1);
            }
            wbuf_lim += cnt;
        }

        if (FD_ISSET(1, &writefds)) {
            if ((cnt = write(1, rbuf + rbuf_pos, rbuf_lim - rbuf_pos)) < 0) {
                perror("write");
                exit(1);
            }
            rbuf_pos += cnt;
            if (rbuf_pos == rbuf_lim)
                rbuf_pos = rbuf_lim = 0;
        }
    }
}
