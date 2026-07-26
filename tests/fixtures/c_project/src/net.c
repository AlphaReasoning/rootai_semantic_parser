/* src/net.c - translation unit exercising: control flow (if/else/for/while/switch),
   pointer arithmetic, raw pointer derefs, format-string sinks,
   unsafe string ops, macro expansions, and taint paths */

#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Conditional preproc block (was previously invisible to parser) ─── */
#ifdef DEBUG
static int g_debug_level = 2;
static void debug_print(const char *msg) {
    fprintf(stderr, "[DBG] %s\n", msg);
}
#endif

/* ── Global state ─────────────────────────────────────────────────────── */
static char g_server_name[256];
static client_ctx_t *g_clients[MAX_CLIENTS];
static int g_client_count = 0;

/* ── net_init ─────────────────────────────────────────────────────────── */
int net_init(void) {
    char *env_name = getenv("SERVER_NAME");           /* taint SOURCE */
    if (env_name != NULL) {
        strcpy(g_server_name, env_name);              /* taint SINK: strcpy */
    } else {
        strncpy(g_server_name, "localhost", 255);
    }
    return 0;
}

/* ── net_accept ───────────────────────────────────────────────────────── */
int net_accept(int server_fd, client_ctx_t *ctx) {
    /* pointer arithmetic on ctx fields */
    uint8_t *buf_ptr = (uint8_t *)ctx->recv_buf;
    size_t offset = 0;
    int ret = 0;

    /* for loop + pointer arithmetic */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i] == NULL) {
            g_clients[i] = ctx;
            g_client_count++;
            buf_ptr += i;                             /* POINTER_ARITH */
            break;
        }
    }

    /* while loop */
    while (offset < MAX_BUF) {
        buf_ptr[offset] = 0;
        offset++;
    }

    return ret;
}

/* ── net_recv ─────────────────────────────────────────────────────────── */
int net_recv(client_ctx_t *ctx, size_t max_len) {
    ssize_t n = read(ctx->fd, ctx->recv_buf, max_len); /* taint SOURCE: read */
    if (n < 0) return -1;
    ctx->recv_buf[n] = '\0';

    /* format string vulnerability via UNSAFE_FMT macro */
    char log_buf[512];
    UNSAFE_FMT(log_buf, ctx->recv_buf);               /* MACRO → sprintf taint SINK */

    /* unsafe pointer dereference */
    if (ctx->overflow_ptr != NULL) {
        *ctx->overflow_ptr = (uint8_t)n;              /* raw ptr deref SINK */
    }

    return (int)n;
}

/* ── net_dispatch ─────────────────────────────────────────────────────── */
void net_dispatch(client_ctx_t *ctx, const char *cmd) {
    /* switch-like if/else chain */
    if (strcmp(cmd, "exec") == 0) {
        /* taint: recv_buf → system */
        system(ctx->recv_buf);                        /* taint SINK: system */
    } else if (strcmp(cmd, "echo") == 0) {
        printf("%s\n", ctx->recv_buf);                /* format sink */
    } else if (strcmp(cmd, "env") == 0) {
        char *val = getenv(ctx->recv_buf);            /* taint SOURCE chained */
        if (val != NULL) {
            SAFE_COPY(ctx->token, val, 63);           /* safe copy via macro */
        }
    } else {
        LOG("unknown command");
    }
}

/* ── net_close ────────────────────────────────────────────────────────── */
void net_close(client_ctx_t *ctx) {
    /* pointer walk to zero-out the token (PII wipe) */
    char *p = ctx->token;
    while (*p) {
        *p++ = 0;                                     /* ptr arithmetic + deref */
    }
    close(ctx->fd);
}

/* ── net_get_env ──────────────────────────────────────────────────────── */
char *net_get_env(const char *name) {
    return getenv(name);                              /* taint SOURCE passthrough */
}
