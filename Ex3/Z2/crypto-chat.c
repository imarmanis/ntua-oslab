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

#include <fcntl.h>
#include <sys/ioctl.h>

#include <sys/stat.h>

#include <crypto/cryptodev.h>

#define BUF_SIZE 64     
#define BLOCK_SIZE 16
#define KEY_SIZE	16  /* AES128 */

int cfd, sd = 0;
struct session_op sess;

void closesd(int x) {
    close(sd);
    exit(1);
}

void closecd(int x) {
    close(cfd);
    close(sd);
    exit(1);
}

void closeses(int x) {
    if (ioctl(cfd, CIOCFSESSION, &sess.ses)) perror("ioctl(CIOCFSESSION)");
    close(cfd);
    close(sd);
    exit(1);
}

void use_error(char *fname)
{
    fprintf(stderr, "Usage: %s [-s port | -c hostname port]\n", fname);
    if (sd != 0) close(sd);
    exit(1);
}

int main(int argc, char *argv[])
{
    int port;
    ssize_t cnt;
    char rbuf[BUF_SIZE];
    char wbuf[BUF_SIZE];
    struct sockaddr_in sa;

    if (argc < 2) use_error(argv[0]);

    signal(SIGPIPE, SIG_IGN);

    if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }
    fprintf(stderr, "Created TCP socket\n");

    signal(SIGINT, closesd);

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
            closesd(0);
        }
        fprintf(stderr, "Bound TCP socket to port %d\n", port);

        if (listen(sd, 1) < 0) {
            perror("listen");
            closesd(0);
        }
        fprintf(stderr, "Waiting for an incoming connection...\n");

        len = sizeof(struct sockaddr_in);
        if ((sd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
            perror("accept");
            closesd(0);
        }
        if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
            perror("could not format IP address");
            closesd(0);
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
            closesd(0);
        }
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
        fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
        if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
            perror("connect");
            closesd(0);
        }
        fprintf(stderr, "Connected.\n");

    } else use_error(argv[0]);



    cfd = open("/dev/crypto", O_RDWR);
    if (cfd < 0) {
        perror("open(/dev/crypto)");
        closesd(0);
    }

    signal(SIGINT, closecd);
    /*  */
    struct crypt_op cryp;
    unsigned char iv[BLOCK_SIZE];
    unsigned char key[KEY_SIZE];

    memset(&sess, 0, sizeof(sess));
    memset(&cryp, 0, sizeof(cryp));
    memset(iv, 0, sizeof(iv));
    memset(key, 0, sizeof(key));

    sess.cipher = CRYPTO_AES_CBC;
    sess.key = key;
    sess.keylen = KEY_SIZE;

    if (ioctl(cfd, CIOCGSESSION, &sess)) {
        perror("ioctl(CIOCGSESSION)");
        closecd(0);
    }

    cryp.ses = sess.ses;
    cryp.len = BUF_SIZE;
    cryp.iv = iv;
    signal(SIGINT, closeses);

    fprintf(stderr, "Chat ready.\n");

    fd_set readfds, writefds;
    uint32_t const L = sizeof(L);
    uint32_t rbuf_pos = 0, wbuf_pos = 0, rbuf_lim = 0, wbuf_lim = 0;

    for (;;) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        if (wbuf_lim == BUF_SIZE) FD_SET(sd, &writefds);
        //lim = BUFSIZE => buffer ready (with header) to write to sd
        if (rbuf_pos == 0) FD_SET(sd, &readfds);
        //pos = 0 => reading from sd
        if (wbuf_lim == 0) FD_SET(0, &readfds);
        //lim = 0 => no stdin input yet
        if (rbuf_pos >= L) FD_SET(1, &writefds);
        // pos >= L => sd read finished (all BUF_SIZE bytes), write to stdout

        if (select(sd + 1, &readfds, &writefds, NULL, NULL) < 0){
            perror("select");
            closeses(0);
        }

        if (FD_ISSET(0, &readfds)) {
            if ((cnt = read(0, wbuf + L, BUF_SIZE - L)) < 0) {
                perror("read");
                closeses(0);
            }
            if (cnt == 0) {
                fprintf(stderr, "Stdin closed ?!\n");
                closeses(0);
            }
            *((uint32_t *) wbuf) = htonl(L + cnt);
            wbuf_lim = BUF_SIZE;
            wbuf_pos = 0;

            cryp.op = COP_ENCRYPT;
            cryp.src = (unsigned char*) wbuf;
            cryp.dst = (unsigned char*) wbuf;

            if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                perror("ioctl(CIOCCRYPT)");
                closeses(0);
            }
        }

        if (FD_ISSET(sd, &writefds)) {
            if ((cnt = write(sd, wbuf + wbuf_pos, wbuf_lim - wbuf_pos)) < 0) {
                perror("write");
                closeses(0);
            }
            wbuf_pos += cnt;
            if (wbuf_pos == wbuf_lim)
                wbuf_pos = wbuf_lim = 0;
        }

        if (FD_ISSET(sd, &readfds)) {
            if ((cnt = read(sd, rbuf + rbuf_lim, BUF_SIZE - rbuf_lim)) < 0) {
                perror("read");
                closeses(0);
            }
            if (cnt == 0) {
                fprintf(stderr, "Peer went away\n");
                closeses(0);
            }
            rbuf_lim += cnt;
            if (rbuf_lim == BUF_SIZE) {
                cryp.op = COP_DECRYPT;
                cryp.src = (unsigned char*) rbuf;
                cryp.dst = (unsigned char*) rbuf;

                if (ioctl(cfd, CIOCCRYPT, &cryp)) {
                    perror("ioctl(CIOCCRYPT)");
                    closeses(0);
                }
                rbuf_pos = L;
                rbuf_lim = ntohl(*((uint32_t *) rbuf));
            }
        }

        if (FD_ISSET(1, &writefds)) {
            if ((cnt = write(1, rbuf + rbuf_pos, rbuf_lim - rbuf_pos)) < 0) {
                perror("write");
                closeses(0);
            }
            rbuf_pos += cnt;
            if (rbuf_pos == rbuf_lim)
                rbuf_pos = rbuf_lim = 0;
        }
    }
}
