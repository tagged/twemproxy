/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <unistd.h>
#include <nc_core.h>
#include <nc_conf.h>
#include <nc_server.h>
#include <nc_proxy.h>

static uint32_t ctx_id; /* context generation */

static void
core_failed_servers_init(struct context *ctx)
{
    int i;

    for (i = 0; i < 2; i++) {
        array_init(&(ctx->failed_servers[i]), 10, sizeof(struct server *));
    }
}

static void
core_failed_servers_deinit(struct context *ctx)
{
    uint32_t i, n, nsize;

    for (i = 0; i < 2; i++) {
        nsize = array_n(&(ctx->failed_servers[i]));
        for (n = 0; n < nsize; n++) {
            /* This is buggy but core_failed_servers_deinit isn't even referenced - failed_servers is 2 arrays */
            array_pop(&(ctx->failed_servers[n]));
        }
        array_deinit(&(ctx->failed_servers[n]));
    }
}

static rstatus_t
core_calc_connections(struct context *ctx)
{
    int status;
    struct rlimit limit;

    status = getrlimit(RLIMIT_NOFILE, &limit);
    if (status < 0) {
        log_error("getrlimit failed: %s", strerror(errno));
        return NC_ERROR;
    }

    ctx->max_nfd = (uint32_t)limit.rlim_cur;
    ctx->max_ncconn = ctx->max_nfd - ctx->max_nsconn - RESERVED_FDS;
    log_debug(LOG_NOTICE, "max fds %"PRIu32" max client conns %"PRIu32" "
              "max server conns %"PRIu32"", ctx->max_nfd, ctx->max_ncconn,
              ctx->max_nsconn);

    return NC_OK;
}

static struct context *
core_ctx_create(struct instance *nci)
{
    rstatus_t status;
    struct context *ctx;

    ctx = nc_alloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->id = ++ctx_id;
    ctx->cf = NULL;
    ctx->stats = NULL;
    ctx->evb = NULL;
    array_null(&ctx->pool);
    array_null(&(ctx->failed_servers[0]));
    array_null(&(ctx->failed_servers[1]));
    ctx->failed_idx = 0;
    ctx->fails = &(ctx->failed_servers[0]);

    ctx->max_timeout = nci->stats_interval;
    ctx->timeout = ctx->max_timeout;
    ctx->max_nfd = 0;
    ctx->max_ncconn = 0;
    ctx->max_nsconn = 0;

    /* parse and create configuration */
    ctx->cf = conf_create(nci->conf_filename);
    if (ctx->cf == NULL) {
        nc_free(ctx);
        return NULL;
    }

    /* initialize server pool from configuration */
    status = server_pool_init(&ctx->pool, &ctx->cf->pool, ctx);
    if (status != NC_OK) {
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /*
     * Get rlimit and calculate max client connections after we have
     * calculated max server connections
     */
    status = core_calc_connections(ctx);
    if (status != NC_OK) {
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    core_failed_servers_init(ctx);

    /* create stats per server pool */
    ctx->stats = stats_create(nci->stats_port, nci->stats_addr, nci->stats_interval,
                              nci->hostname, &ctx->pool);
    if (ctx->stats == NULL) {
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /* initialize event handling for client, proxy and server */
    ctx->evb = event_base_create(EVENT_SIZE, &core_core);
    if (ctx->evb == NULL) {
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /* connect sentinel always, connect servers if preconnect is true */
    status = server_pool_connect(ctx);
    if (status != NC_OK) {
        server_pool_disconnect(ctx);
        event_base_destroy(ctx->evb);
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    /* initialize proxy per server pool */
    status = proxy_init(ctx);
    if (status != NC_OK) {
        server_pool_disconnect(ctx);
        event_base_destroy(ctx->evb);
        stats_destroy(ctx->stats);
        server_pool_deinit(&ctx->pool);
        conf_destroy(ctx->cf);
        nc_free(ctx);
        return NULL;
    }

    log_debug(LOG_VVERB, "created ctx %p id %"PRIu32"", ctx, ctx->id);

    return ctx;
}

static void
core_ctx_destroy(struct context *ctx)
{
    log_debug(LOG_VVERB, "destroy ctx %p id %"PRIu32"", ctx, ctx->id);
    proxy_deinit(ctx);
    server_pool_disconnect(ctx);
    event_base_destroy(ctx->evb);
    stats_destroy(ctx->stats);
    server_pool_deinit(&ctx->pool);
    conf_destroy(ctx->cf);
    nc_free(ctx);
}

struct context *
core_start(struct instance *nci)
{
    struct context *ctx;

    mbuf_init(nci);
    msg_init();
    conn_init();

    ctx = core_ctx_create(nci);
    if (ctx != NULL) {
        nci->ctx = ctx;
        return ctx;
    }

    conn_deinit();
    msg_deinit();
    mbuf_deinit();

    return NULL;
}

void
core_stop(struct context *ctx)
{
    conn_deinit();
    msg_deinit();
    mbuf_deinit();
    core_ctx_destroy(ctx);
}

static rstatus_t
core_recv(struct context *ctx, struct conn *conn)
{
    rstatus_t status;

    status = conn->recv(ctx, conn);
    if (status != NC_OK) {
        log_debug(LOG_INFO, "recv on %c %d failed: %s",
                  conn->client ? 'c' : (conn->proxy ? 'p' : 's'), conn->sd,
                  strerror(errno));
    }

    return status;
}

static rstatus_t
core_send(struct context *ctx, struct conn *conn)
{
    rstatus_t status;

    status = conn->send(ctx, conn);
    if (status != NC_OK) {
        log_debug(LOG_NOTICE, "send on %c %d failed: status: %d errno: %d %s",
                  conn->client ? 'c' : (conn->proxy ? 'p' : 's'), conn->sd,
                  status, errno, strerror(errno));
    }

    return status;
}

static void
core_close(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    char type, *addrstr;

    ASSERT(conn->sd > 0);

    if (conn->client) {
        type = 'c';
        addrstr = nc_unresolve_peer_desc(conn->sd);
    } else {
        type = conn->proxy ? 'p' : 's';
        addrstr = nc_unresolve_addr(conn->addr, conn->addrlen);
    }
    // Certain clients (e.g. PHP) frequently open and close connections by nature.
    // Log at a lower severity.
    log_debug(LOG_INFO, "close %c %d '%s' on event %04"PRIX32" eof %d done "
              "%d rb %zu sb %zu%c %s", type, conn->sd, addrstr, conn->events,
              conn->eof, conn->done, conn->recv_bytes, conn->send_bytes,
              conn->err ? ':' : ' ', conn->err ? strerror(conn->err) : "");

    status = event_del_conn(ctx->evb, conn);
    if (status < 0) {
        log_warn("event del conn %c %d failed, ignored: %s",
                 type, conn->sd, strerror(errno));
    }

    conn->close(ctx, conn);
}

static void
core_error(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    char type = conn->client ? 'c' : (conn->proxy ? 'p' : 's');

    status = nc_get_soerror(conn->sd);
    if (status < 0) {
        log_warn("get soerr on %c %d failed, ignored: %s", type, conn->sd,
                  strerror(errno));
    }
    conn->err = errno;

    core_close(ctx, conn);
}

/* Try to re-establish any failed connections to servers once the retry timeout has elapsed for a server. */
/* This is periodically called from core_timeout */
static void
retry_connection(struct context *ctx)
{
    struct array *servers;
    int idx;
    struct server *server;
    int64_t now;
    uint32_t i, nsize;
    rstatus_t status;

    /* Alternate between two lists of failed servers (to only retry a given server once here?) */
    /* add_failed_server() has a check to ensure there are no duplicates, which is useful if connecting */
    /* attempts are slow or to make the state machine for reconnecting easier to reason about. */
    servers = ctx->fails;
    idx = (ctx->failed_idx == 0) ? 1 : 0;

    ctx->failed_idx = idx;
    ctx->fails = &(ctx->failed_servers[idx]);

    now = nc_usec_now();
    nsize = array_n(servers);
    if (nsize == 0) {
        return;
    }

    for (i = 0; i < nsize; i++) {
        server = *(struct server **)array_pop(servers);
        if (server->next_retry == 0 || server->next_retry < now) {
            status = server_reconnect(ctx, server);
            if (status != NC_OK) {
                add_failed_server(ctx, server);
            }
        } else {
            add_failed_server(ctx, server);
        }
        /* Postcondition: A connection in this server is either */
        /* 1. already connected */
        /* 2. reconnecting, or */
        /* 3. added to the opposite failed server list to retry later */
    }
}

static void
core_timeout(struct context *ctx)
{
    for (;;) {
        struct msg *msg;
        struct conn *conn;
        int64_t now, then;

        msg = msg_tmo_min();
        if (msg == NULL) {
            ctx->timeout = ctx->max_timeout;
            break;
        }

        /* skip over req that are in-error or done */

        if (msg->error || msg->done) {
            msg_tmo_delete(msg);
            break;
        }

        /*
         * timeout expired req and all the outstanding req on the timing
         * out server
         */

        conn = msg->tmo_rbe.data;
        then = msg->tmo_rbe.key;

        now = nc_msec_now();
        if (now < then) {
            int delta = (int)(then - now);
            ctx->timeout = MIN(delta, ctx->max_timeout);
            return;
        }

        log_debug(LOG_INFO, "req %"PRIu64" on s %d timedout", msg->id, conn->sd);

        msg_tmo_delete(msg);
        conn->err = ETIMEDOUT;

        core_close(ctx, conn);
    }

    retry_connection(ctx);
}

rstatus_t
core_core(void *arg, uint32_t events)
{
    rstatus_t status;
    struct conn *conn = arg;
    struct context *ctx;

    if (conn->owner == NULL) {
        log_warn("conn is already unrefed!");
        return NC_OK;
    }

    ctx = conn_to_ctx(conn);

    log_debug(LOG_VVERB, "event %04"PRIX32" on %c %d", events,
              conn->client ? 'c' : (conn->proxy ? 'p' : 's'), conn->sd);

    conn->events = events;
    conn->restore(ctx, conn);

    /* error takes precedence over read | write */
    if (events & EVENT_ERR) {
        core_error(ctx, conn);
        return NC_ERROR;
    }

    /* read takes precedence over write */
    if (events & EVENT_READ) {
        status = core_recv(ctx, conn);
        if (status != NC_OK || conn->done || conn->err) {
            core_close(ctx, conn);
            return NC_ERROR;
        }
    }

    if (events & EVENT_WRITE) {
        status = core_send(ctx, conn);
        if (status != NC_OK || conn->done || conn->err) {
            core_close(ctx, conn);
            return NC_ERROR;
        }
    }

    return NC_OK;
}

rstatus_t
core_loop(struct context *ctx)
{
    int nsd;

    nsd = event_wait(ctx->evb, ctx->timeout);
    if (nsd < 0) {
        return nsd;
    }

    core_timeout(ctx);

    stats_swap(ctx->stats);

    return NC_OK;
}
