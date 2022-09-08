#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/errno.h>
#include "list.h"
#include "ae/ae.h"
#include "ae/anet.h"

#define DEBUG 1

#define fatal(fmt, ...) do { \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    exit(1); \
} while (0)

#if DEBUG 
    #define debug(fmt, ...) do { \
        fprintf(stdout, fmt, ##__VA_ARGS__); \
    } while (0)
#else
    #define debug()
#endif

#define BUFSIZE 8192

aeEventLoop *el = NULL; 
char err[256] = {0};
LIST_HEAD(redirector_list);

void writable_handler(aeEventLoop *el, int fd, void *data, int mask);
void readable_handler(aeEventLoop *el, int fd, void *data, int mask);

typedef struct _connection connection_t;
typedef struct _session session_t;
typedef struct _redirector redirector_t;

struct redirect_info {
    char src_addr[16];
    int src_port;
    char target_addr[16];
    int target_port;
};

struct _buffer {
    char data[BUFSIZE];
    int len;
    int pos;
};

struct _session {
    struct list_head link;
    struct _redirector *redirector;
    int src_fd;
    int target_fd;

    struct _buffer tosrc_buf;
    struct _buffer totarget_buf;
};

struct _redirector {
    struct list_head link;
    struct redirect_info info;
    struct list_head sessions;
    int fd;
};

/**
 * [source ip]:[source port][space][target ip][target port]
 * eg. 0.0.0.0:123 10.10.10.10:123
 */
int parse_redirect_info(char *data, struct redirect_info *info) {
    if (data == NULL) return -1;
    char *src, *target, *addr;
    int port;
    src = strtok(data, " ");
    target = strtok(NULL, " ");

    addr = strtok(src, ":");
    port = atoi(strtok(NULL, ":"));
    memcpy(info->src_addr, addr, sizeof(info->src_addr) - 1);
    info->src_port = port;

    addr = strtok(target, ":");
    port = atoi(strtok(NULL, ":"));
    memcpy(info->target_addr, addr, sizeof(info->target_addr) - 1);
    info->target_port = port;
    return 0;
}

int set_socket_opts(int fd) {
    if (anetNonBlock(err, fd) < 0) {
        fprintf(stderr, "failed to set non block:%s\n", err);
        return -1;
    }

    if (anetEnableTcpNoDelay(err, fd) < 0) {
        fprintf(stderr, "failed to enable tcp no delay:%s\n", err);
        return -1;
    }
    return 0;
}

void free_session(session_t *sess) {
    struct redirect_info *info = &sess->redirector->info;
    debug("connection close:[%s:%d]->[%s:%d]\n", info->src_addr, info->src_port,
            info->target_addr, info->target_port);
    aeDeleteFileEvent(el, sess->src_fd, AE_READABLE | AE_WRITABLE);
    aeDeleteFileEvent(el, sess->target_fd, AE_READABLE | AE_WRITABLE);
    close(sess->src_fd);
    close(sess->target_fd);
    list_del(&sess->link);
    free(sess);
}

void writable_handler(aeEventLoop *el, int fd, void *data, int mask) {
    session_t *sess = (session_t *)data;
    struct _buffer *tobuf = NULL;
    int delfd, createfd;
    if (fd == sess->src_fd) {
        tobuf = &sess->tosrc_buf;
        delfd = sess->src_fd;
        createfd = sess->target_fd;
    } else if (fd == sess->target_fd) {
        tobuf = &sess->totarget_buf;
        delfd = sess->target_fd;
        createfd = sess->src_fd;
    } else {
        fatal("error");
    }
    if (tobuf->len == tobuf->pos) {
        aeDeleteFileEvent(el, delfd, AE_WRITABLE);
        aeCreateFileEvent(el, createfd, AE_READABLE, readable_handler, sess);
    }
    int len = tobuf->len - tobuf->pos;
    int nwrite = write(fd, tobuf->data, len);
    if (nwrite < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        goto fail;
    }
    tobuf->pos += nwrite;
    return;
fail:
    free_session(sess);
}

void readable_handler(aeEventLoop *el, int fd, void *data, int mask) {
    session_t *sess = (session_t *)data;
    struct _buffer *tobuf = NULL;
    int delfd, createfd;
    if (fd == sess->src_fd) {
        tobuf = &sess->totarget_buf;
        delfd = sess->src_fd;
        createfd = sess->target_fd;
    } else if (fd == sess->target_fd) {
        tobuf = &sess->tosrc_buf;
        delfd = sess->target_fd;
        createfd = sess->src_fd;
    } else {
        fatal("error\n");
    }
    int nread = read(fd, tobuf->data, BUFSIZE);
    if (nread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        goto fail;
    } else if (nread == 0) {
        goto fail;
    } else {
        tobuf->pos = 0;
        tobuf->len = nread;
        aeDeleteFileEvent(el, delfd, AE_READABLE);
        aeCreateFileEvent(el, createfd, AE_WRITABLE, writable_handler, sess);
    }
    return;
fail:
    free_session(sess);

}

void accept_handler(aeEventLoop *el, int fd, void *data, int mask) {
    int srcfd = anetTcpAccept(err, fd, NULL, 0, NULL);
    if (srcfd < 0) {
        fprintf(stderr, "failed to accept:%s\n", err);
        return;
    }
    if (set_socket_opts(srcfd) < 0) {
        close(srcfd);
        return;
    }
    redirector_t *r = (redirector_t*)data;
    // connect to target addr
    int targetfd = anetTcpConnect(err, r->info.target_addr, r->info.target_port);
    if (targetfd < 0) {
        fprintf(stderr, "failed to connect [%s:%d]\n", r->info.target_addr, r->info.target_port);
        close(srcfd);
        return;
    }
    if (set_socket_opts(targetfd) < 0) {
        close(srcfd);
        close(targetfd);
        return;
    }

    session_t *sess = calloc(1, sizeof(session_t));
    sess->src_fd = srcfd;
    sess->target_fd = targetfd;
    sess->redirector = r;

    if (aeCreateFileEvent(el, srcfd, AE_READABLE, readable_handler, sess) < 0) {
        fprintf(stderr, "failed to create event, errno:%d\n", errno);
        free(sess);
        close(srcfd);
        close(targetfd);
        return;
    }

    if (aeCreateFileEvent(el, targetfd, AE_READABLE, readable_handler, sess) < 0) {
        fprintf(stderr, "failed to create event, errno:%d\n", errno);
        free(sess);
        close(srcfd);
        close(targetfd);
        return;
    }
    struct redirect_info *info = &sess->redirector->info;
    debug("new connection:[%s:%d]->[%s:%d]\n", info->src_addr, info->src_port,
            info->target_addr, info->target_port);
    list_add(&sess->link, &r->sessions);
}

int new_redirector(struct redirect_info *info) {
    int fd = anetTcpServer(err, info->src_port, info->src_addr, 512);
    if (fd < 0) {
        fprintf(stderr, "failed to listen %s:%d, %s\n", info->src_addr, info->src_port, err);
        return -1;
    }
    if (set_socket_opts(fd) < 0) {
        return -1;
    }

    redirector_t *ri = malloc(sizeof(redirector_t));
    ri->fd = fd;
    ri->info = *info;
    INIT_LIST_HEAD(&ri->sessions);
    if (aeCreateFileEvent(el, fd, AE_READABLE, accept_handler, ri) < 0) {
        fprintf(stderr, "failed to create event, errno:%d\n", errno);
        free(ri);
        return -1;
    }
    list_add_tail(&ri->link, &redirector_list);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fatal("invalid argument\n");
    }
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        fatal("failed to open %s\n", argv[1]);
    }
    el = aeCreateEventLoop(512);
    char buf[128] = {0};
    struct redirect_info info;
    while (fgets(buf, sizeof(buf), fp)) {
        if (parse_redirect_info(buf, &info) < 0) {
            fprintf(stdout, "parse fail\n");
        }
        if (new_redirector(&info) < 0) {
            continue;
        }
        debug("src ip:%s, src port:%d, target ip:%s, target port:%d start\n", 
                info.src_addr, info.src_port, info.target_addr, info.target_port);
    }
    fclose(fp);
    aeMain(el);
    // free redirector list
    struct list_head *pos;
    list_for_each(pos, &redirector_list) {
        redirector_t *ri = list_entry(pos, redirector_t, link);
        free(ri);
    }
    if (el) 
        aeDeleteEventLoop(el);
    return 0;
}
