/* include/net.h - header exercising: struct layouts, typedefs,
   function prototypes, and conditional compilation */

#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>

#define MAX_BUF     4096
#define MAX_CLIENTS 128
#define SAFE_COPY(dst, src, n) strncpy((dst), (src), (n))
#define UNSAFE_FMT(buf, fmt)   sprintf((buf), (fmt))   /* format-string sink */

#ifdef DEBUG
#  define LOG(msg) fprintf(stderr, "[DEBUG] %s\n", (msg))
#else
#  define LOG(msg) ((void)0)
#endif

typedef uint32_t   net_addr_t;
typedef uint16_t   net_port_t;
typedef unsigned char * byte_ptr_t;

typedef struct {
    net_addr_t  addr;
    net_port_t  port;
    char        hostname[256];      /* potential overflow target */
} endpoint_t;

typedef struct client_ctx {
    int         fd;
    endpoint_t  remote;
    char        recv_buf[MAX_BUF];  /* taint landing zone */
    char        token[64];          /* PII */
    uint8_t    *overflow_ptr;       /* raw pointer field */
    int         authenticated;
} client_ctx_t;

union payload_u {
    uint32_t    as_int;
    float       as_float;
    char        as_bytes[4];
};

/* Function prototypes */
int  net_init(void);
int  net_accept(int server_fd, client_ctx_t *ctx);
int  net_recv(client_ctx_t *ctx, size_t max_len);
void net_dispatch(client_ctx_t *ctx, const char *cmd);
void net_close(client_ctx_t *ctx);
char *net_get_env(const char *name);

#endif /* NET_H */
