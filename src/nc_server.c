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
#include <nc_server.h>
#include <nc_sentinel.h>
#include <nc_conf.h>
#include <event/nc_event.h>

static void
server_resolve(struct server *server, struct conn *conn)
{
    rstatus_t status;

    status = nc_resolve(&server->addrstr, server->port, &server->info);
    if (status != NC_OK) {
        conn->err = EHOSTDOWN;
        conn->done = 1;
        return;
    }

    conn->family = server->info.family;
    conn->addrlen = server->info.addrlen;
    conn->addr = (struct sockaddr *)&server->info.addr;
}

void
server_ref(struct conn *conn, void *owner)
{
    struct server *server = owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->owner == NULL);

    server_resolve(server, conn);

    server->ns_conn_q++;
    TAILQ_INSERT_TAIL(&server->s_conn_q, conn, conn_tqe);

    conn->owner = owner;

    log_debug(LOG_VVERB, "ref conn %p owner %p into '%.*s", conn, server,
              server->pname.len, server->pname.data);
}

void
server_unref(struct conn *conn)
{
    struct server *server;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->owner != NULL);

    server = conn->owner;
    conn->owner = NULL;

    ASSERT(server->ns_conn_q != 0);
    server->ns_conn_q--;
    TAILQ_REMOVE(&server->s_conn_q, conn, conn_tqe);

    log_debug(LOG_VVERB, "unref conn %p owner %p from '%.*s'", conn, server,
              server->pname.len, server->pname.data);
}

int
server_timeout(struct conn *conn)
{
    struct server *server;
    struct server_pool *pool;

    ASSERT(!conn->client && !conn->proxy);

    server = conn->owner;
    pool = server->owner;

    return pool->timeout;
}

bool
server_active(struct conn *conn)
{
    ASSERT(!conn->client && !conn->proxy);

    if (!TAILQ_EMPTY(&conn->imsg_q)) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (!TAILQ_EMPTY(&conn->omsg_q)) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (conn->rmsg != NULL) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    if (conn->smsg != NULL) {
        log_debug(LOG_VVERB, "s %d is active", conn->sd);
        return true;
    }

    log_debug(LOG_VVERB, "s %d is inactive", conn->sd);

    return false;
}

static rstatus_t
server_each_set_owner(void *elem, void *data)
{
    struct server *s = elem;
    struct server_pool *sp = data;

    s->owner = sp;

    return NC_OK;
}

static rstatus_t
server_each_set_sentinel(void *elem, void *data)
{
    struct server *s = elem;

    s->sentinel = 1;

    return NC_OK;
}

static rstatus_t
server_pool_each_set_failover(void *elem, void *data)
{
    struct server_pool *sp = elem, *pool;
    struct array *pool_array = data;
    uint32_t pool_index;

    if (string_empty(&sp->failover_name)) {
        return NC_OK;
    }
    for (pool_index = 0; pool_index < array_n(pool_array); pool_index++) {
        pool = array_get_known_type(pool_array, pool_index, struct server_pool);

        if (string_compare(&pool->name, &sp->failover_name) == 0 &&
            pool->redis == sp->redis) {
            sp->failover = pool;
            return NC_OK;
        }
    }
    return NC_ERROR;
}

static rstatus_t
server_pool_validate_no_failover_loop(struct array *pool_array)
{
    uint32_t pool_index;

    for (pool_index = 0; pool_index < array_n(pool_array); pool_index++) {
        struct server_pool * const pool = array_get_known_type(pool_array, pool_index, struct server_pool);
        struct server_pool *next = pool;
        struct server_pool *next2 = pool->failover;

        // Each loop, advance next by one position and next2 by two positions.
        // If there is an infinite loop, they will eventually be equal.
        // See https://en.wikipedia.org/wiki/Cycle_detection#Tortoise_and_hare
        while (next != NULL && next2 != NULL) {
            if (next == next2) {
                log_error("Detected infinite recursion in failover pool configuration for pool '%.*s'",
                        pool->name.len, pool->name.data);
                return NC_ERROR;
            }
            next = next->failover;
            next2 = next2->failover;
            if (next2 == NULL) {
                break;
            }
            next2 = next2->failover;
        }
    }
    return NC_OK;
}

rstatus_t
server_init(struct array *server, struct array *conf_server,
            struct server_pool *sp, bool sentinel)
{
    rstatus_t status;
    uint32_t nserver;

    nserver = array_n(conf_server);
    if (nserver == 0) {
        /* no sentinels is configured */
        ASSERT(sentinel);
        return NC_OK;
    }

    ASSERT(array_n(server) == 0);

    status = array_init(server, nserver, sizeof(struct server));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf server to server */
    status = array_each(conf_server, conf_server_each_transform, server);
    if (status != NC_OK) {
        server_deinit(server);
        return status;
    }
    ASSERT(array_n(server) == nserver);

    /* set server owner */
    status = array_each(server, server_each_set_owner, sp);
    if (status != NC_OK) {
        server_deinit(server);
        return status;
    }

    if (sentinel) {
        /* set server sentinel flag */
        status = array_each(server, server_each_set_sentinel, NULL);
        if (status != NC_OK) {
            server_deinit(server);
            return status;
        }
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" servers in pool %"PRIu32" '%.*s'",
              nserver, sp->idx, sp->name.len, sp->name.data);

    return NC_OK;
}

void
server_deinit(struct array *server)
{
    uint32_t i, nserver;

    for (i = 0, nserver = array_n(server); i < nserver; i++) {
        struct server *s;

        s = array_pop(server);
        ASSERT(TAILQ_EMPTY(&s->s_conn_q) && s->ns_conn_q == 0);
    }
    array_deinit(server);
}

struct conn *
server_conn(struct server *server)
{
    struct server_pool *pool;
    struct conn *conn;

    pool = server->owner;

    /*
     * FIXME: handle multiple server connections per server and do load
     * balancing on it. Support multiple algorithms for
     * 'server_connections:' > 0 key
     */

    if (server->ns_conn_q < pool->server_connections) {
        return conn_get(server, false, pool->redis);
    }
    ASSERT(server->ns_conn_q == pool->server_connections);

    /*
     * Pick a server connection from the head of the queue and insert
     * it back into the tail of queue to maintain the lru order
     */
    conn = TAILQ_FIRST(&server->s_conn_q);
    ASSERT(!conn->client && !conn->proxy);

    TAILQ_REMOVE(&server->s_conn_q, conn, conn_tqe);
    TAILQ_INSERT_TAIL(&server->s_conn_q, conn, conn_tqe);

    return conn;
}

static rstatus_t
server_each_preconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server *server;
    struct server_pool *pool;
    struct conn *conn;

    server = elem;
    pool = server->owner;

    conn = server_conn(server);
    if (conn == NULL) {
        return NC_ENOMEM;
    }

    status = server_connect(pool->ctx, server, conn);
    if (status != NC_OK) {
        log_warn("connect to server '%.*s' failed, ignored: %s",
                 server->pname.len, server->pname.data, strerror(errno));
        server_close(pool->ctx, conn);
    }

    return NC_OK;
}

static rstatus_t
server_each_disconnect(void *elem, void *data)
{
    struct server *server;
    struct server_pool *pool;

    server = elem;
    pool = server->owner;

    while (!TAILQ_EMPTY(&server->s_conn_q)) {
        struct conn *conn;

        ASSERT(server->ns_conn_q > 0);

        conn = TAILQ_FIRST(&server->s_conn_q);
        conn->close(pool->ctx, conn);
    }

    return NC_OK;
}

static void
server_failure(struct context *ctx, struct server *server)
{
    struct server_pool *pool = server->owner;
    int64_t now;
    rstatus_t status;
    bool is_reconnect;

    /* sentinel do not need eject */
    if (server->sentinel) {
        return;
    }

    log_debug(LOG_VERB, "server '%.*s' failure count %"PRIu32,
              server->pname.len, server->pname.data, server->failure_count);

    now = nc_usec_now();
    if (now < 0) {
        return;
    }

    server->next_retry = now + pool->server_retry_timeout;

    server->failure_count++;
    is_reconnect = (server->fail != FAIL_STATUS_NORMAL);

    if (is_reconnect) {
        add_failed_server(ctx, server);
        return;
    }

    stats_server_set_ts(ctx, server, server_ejected_at, now);

    log_debug(LOG_NOTICE, "update pool %"PRIu32" '%.*s' to delete server '%.*s' "
              "for next %"PRIu32" secs", pool->idx, pool->name.len,
              pool->name.data, server->pname.len, server->pname.data,
              pool->server_retry_timeout / 1000 / 1000);

    stats_pool_incr(ctx, pool, server_ejects);

    server->failure_count = 0;

    /* BEFORE updating the ketama/modulo/random distribution to remove failed servers, mark the server as failed. */
    add_failed_server(ctx, server);

    /* If auto_eject_hosts is false, we don't need to recompute the distribution because all hosts remain in the distribution. But we do need to mark it as failed above. */
    if (pool->auto_eject_hosts) {
        status = server_pool_run(pool);
        if (status != NC_OK) {
            log_error("updating pool %"PRIu32" '%.*s' failed: %s", pool->idx,
                      pool->name.len, pool->name.data, strerror(errno));
        }
    }
}

static void
server_close_stats(struct context *ctx, struct server *server, err_t err,
                   unsigned eof, unsigned connected)
{
    if (connected) {
        stats_server_decr(ctx, server, server_connections);
    }

    if (eof) {
        stats_server_incr(ctx, server, server_eof);
        return;
    }

    switch (err) {
    case ETIMEDOUT:
        stats_server_incr(ctx, server, server_timedout);
        break;
    case EPIPE:
    case ECONNRESET:
    case ECONNABORTED:
    case ECONNREFUSED:
    case ENOTCONN:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTDOWN:
    case EHOSTUNREACH:
    default:
        stats_server_incr(ctx, server, server_err);
        break;
    }
}

void
server_close(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg, *nmsg; /* current and next message */
    struct conn *c_conn;    /* peer client connection */

    ASSERT(!conn->client && !conn->proxy);

    server_close_stats(ctx, conn->owner, conn->err, conn->eof,
                       conn->connected);

    conn->connected = false;

    if (conn->sd < 0) {
        server_failure(ctx, conn->owner);
        conn->unref(conn);
        conn_put(conn);
        return;
    }

    for (msg = TAILQ_FIRST(&conn->imsg_q); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, s_tqe);

        /* dequeue the message (request) from server inq - it hasn't been sent yet */
        conn->dequeue_inq(ctx, conn, msg);

        /*
         * Don't send any error response, if
         * 1. request is tagged as noreply or,
         * 2. client has already closed its connection
         */
        if (msg->swallow || msg->noreply) {
            log_debug(LOG_INFO, "close s %d swallow req %"PRIu64" len %"PRIu32
                      " type %d", conn->sd, msg->id, msg->mlen, msg->type);
            /* Assumes that the server status is always set to FAIL_STATUS_ERR_TRY_HEARTBEAT AFTER the server is closed */
            if (msg->heartbeat) {
                c_conn = msg->owner;
                ASSERT(c_conn->client);
                ASSERT(!c_conn->proxy);
                if (c_conn->owner != NULL) {
                    // sets c_conn->owner to null as a side effect
                    log_debug(LOG_INFO, "closing fake connection %d to %d for heartbeat, req %"PRIu64" len %"PRIu32
                          " type %d", c_conn->sd, conn->sd, msg->id, msg->mlen, msg->type);
                    c_conn->unref(c_conn);
                    conn_put(c_conn);
                }
            }
            req_put(msg);
        } else {
            c_conn = msg->owner;
            ASSERT(c_conn->client && !c_conn->proxy);

            msg->done = 1;
            msg->error = 1;
            msg->err = conn->err;

            if (msg->frag_owner != NULL) {
                msg->frag_owner->nfrag_done++;
            }

            if (req_done(c_conn, TAILQ_FIRST(&c_conn->omsg_q))) {
                event_add_out(ctx->evb, msg->owner);
            }

            log_debug(LOG_NOTICE, "close s %d schedule error for req %"PRIu64" "
                      "len %"PRIu32" type %d from c %d%c %s", conn->sd, msg->id,
                      msg->mlen, msg->type, c_conn->sd, conn->err ? ':' : ' ',
                      conn->err ? strerror(conn->err): " ");
        }
    }
    ASSERT(TAILQ_EMPTY(&conn->imsg_q));

    for (msg = TAILQ_FIRST(&conn->omsg_q); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, s_tqe);

        /* dequeue the message (request) from server outq - it was sent and has an unprocessed response */
        conn->dequeue_outq(ctx, conn, msg);

        if (msg->swallow) {
            log_debug(LOG_INFO, "close s %d swallow req %"PRIu64" len %"PRIu32
                      " type %d", conn->sd, msg->id, msg->mlen, msg->type);
            if (msg->heartbeat) {
                c_conn = msg->owner;
                ASSERT(c_conn->client);
                ASSERT(!c_conn->proxy);
                if (c_conn->owner != NULL) {
                    log_debug(LOG_INFO, "closing fake connection %d to %d for heartbeat, req %"PRIu64" len %"PRIu32
                          " type %d", c_conn->sd, conn->sd, msg->id, msg->mlen, msg->type);
                    c_conn->unref(c_conn);
                    conn_put(c_conn);
                }
            }
            req_put(msg);
        } else {
            c_conn = msg->owner;
            ASSERT(c_conn->client && !c_conn->proxy);

            msg->done = 1;
            msg->error = 1;
            msg->err = conn->err;
            if (msg->frag_owner != NULL) {
                msg->frag_owner->nfrag_done++;
            }

            if (req_done(c_conn, TAILQ_FIRST(&c_conn->omsg_q))) {
                event_add_out(ctx->evb, msg->owner);
            }

            log_debug(LOG_NOTICE, "close s %d schedule error for req %"PRIu64" "
                      "len %"PRIu32" type %d from c %d%c %s", conn->sd, msg->id,
                      msg->mlen, msg->type, c_conn->sd, conn->err ? ':' : ' ',
                      conn->err ? strerror(conn->err): " ");
        }
    }
    ASSERT(TAILQ_EMPTY(&conn->omsg_q));

    msg = conn->rmsg;
    if (msg != NULL) {
        conn->rmsg = NULL;

        ASSERT(!msg->request);
        ASSERT(msg->peer == NULL);

        rsp_put(msg);

        log_debug(LOG_NOTICE, "close s %d discarding rsp %"PRIu64" len %"PRIu32" "
                  "in error", conn->sd, msg->id, msg->mlen);
    }

    ASSERT(conn->smsg == NULL);

    server_failure(ctx, conn->owner);

    conn->unref(conn);

    status = close(conn->sd);
    if (status < 0) {
        log_error("close s %d failed, ignored: %s", conn->sd, strerror(errno));
    }
    conn->sd = -1;

    conn_put(conn);
}

rstatus_t
server_connect(struct context *ctx, struct server *server, struct conn *conn)
{
    rstatus_t status;

    ASSERT(!conn->client && !conn->proxy);

    if (conn->err) {
      ASSERT(conn->done && conn->sd < 0);
      errno = conn->err;
      return NC_ERROR;
    }

    if (conn->sd > 0) {
        /* already connected on server connection */
        return NC_OK;
    }

    log_debug(LOG_VVERB, "connect to server '%.*s'", server->pname.len,
              server->pname.data);

    conn->sd = socket(conn->family, SOCK_STREAM, 0);
    if (conn->sd < 0) {
        log_error("socket for server '%.*s' failed: %s", server->pname.len,
                  server->pname.data, strerror(errno));
        status = NC_ERROR;
        goto error;
    }

    status = nc_set_nonblocking(conn->sd);
    if (status != NC_OK) {
        log_error("set nonblock on s %d for server '%.*s' failed: %s",
                  conn->sd, server->pname.len, server->pname.data,
                  strerror(errno));
        goto error;
    }

    if (server->pname.data[0] != '/') {
        status = nc_set_tcpnodelay(conn->sd);
        if (status != NC_OK) {
            log_warn("set tcpnodelay on s %d for server '%.*s' failed, ignored: %s",
                     conn->sd, server->pname.len, server->pname.data,
                     strerror(errno));
        }
    }

    status = event_add_conn(ctx->evb, conn);
    if (status != NC_OK) {
        log_error("event add conn s %d for server '%.*s' failed: %s",
                  conn->sd, server->pname.len, server->pname.data,
                  strerror(errno));
        goto error;
    }

    ASSERT(!conn->connecting && !conn->connected);

    status = connect(conn->sd, conn->addr, conn->addrlen);
    if (status != NC_OK) {
        if (errno == EINPROGRESS) {
            conn->connecting = 1;
            log_debug(LOG_DEBUG, "connecting on s %d to server '%.*s'",
                      conn->sd, server->pname.len, server->pname.data);
            return NC_OK;
        }

        log_error("connect on s %d to server '%.*s' failed: %s", conn->sd,
                  server->pname.len, server->pname.data, strerror(errno));

        goto error;
    }

    ASSERT(!conn->connecting);
    conn->connected = 1;
    log_debug(LOG_NOTICE, "connected on s %d to server '%.*s'", conn->sd,
              server->pname.len, server->pname.data);

    return NC_OK;

error:
    conn->err = errno;
    return status;
}

void
server_connected(struct context *ctx, struct conn *conn)
{
    struct server *server = conn->owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->connecting && !conn->connected);

    stats_server_incr(ctx, server, server_connections);

    conn->connecting = 0;
    conn->connected = 1;

    conn->post_connect(ctx, conn, server);

    log_debug(LOG_NOTICE, "connected on s %d to server '%.*s'", conn->sd,
              server->pname.len, server->pname.data);
}

void
server_ok(struct context *ctx, struct conn *conn)
{
    struct server *server = conn->owner;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->connected);

    if (server->failure_count != 0) {
        log_debug(LOG_VERB, "reset server '%.*s' failure count from %"PRIu32
                  " to 0", server->pname.len, server->pname.data,
                  server->failure_count);
        server->failure_count = 0;
        server->next_retry = 0LL;
    }
}

struct server*
server_find_by_name(struct context *ctx, struct server_pool *server_pool, struct string *server_name)
{
    struct server *server;
    uint32_t i;

    server = NULL;
    for(i = 0; i < array_n(&server_pool->server); i++) {
        server = array_get_known_type(&server_pool->server, i, struct server);
        if (!string_compare(&server->name, server_name)) {
            break;
        } else {
            server = NULL;
        }
    }

    return server;
}

static rstatus_t
server_set_address(struct server *server, struct string *server_ip, int server_port)
{
    rstatus_t status;
    struct conf_server *conf_server;
    char pname_buf[NC_PNAME_MAXLEN];

    conf_server = server->conf_server;

    /* update conf_server's pname used for conf rewrite */
    string_deinit(&conf_server->pname);
    nc_snprintf(pname_buf, NC_PNAME_MAXLEN, "%.*s:%d:%d",
            server_ip->len, server_ip->data, server_port, server->weight);
    status = string_copy(&conf_server->pname, (uint8_t *)pname_buf, (uint32_t)(nc_strlen(pname_buf)));
    if (status != NC_OK) {
        return status;
    }

    /* update conf_server's addrstr used for connection */
    string_deinit(&conf_server->addrstr);
    status = string_duplicate(&conf_server->addrstr, server_ip);
    if (status != NC_OK) {
        return status;
    }

    /* make server's pname and addrstr points to conf_server's */
    server->pname = conf_server->pname;
    server->addrstr = conf_server->addrstr;
    conf_server->port = (uint16_t)server_port;
    server->port = (uint16_t)server_port;

    return NC_OK;
}

static void
server_conn_done(struct server *server)
{
    struct conn *conn;

    TAILQ_FOREACH(conn, &server->s_conn_q, conn_tqe) {
        conn->done = 1;
    }
}

rstatus_t
server_switch(struct context *ctx, struct server *server,
        struct string *server_ip, int server_port)
{
    rstatus_t status;
    struct server_pool *server_pool;
    struct string pname;
    char pname_buf[NC_PNAME_MAXLEN];

    string_init(&pname);
    nc_snprintf(pname_buf, NC_PNAME_MAXLEN, "%.*s:%d:%d",
            server_ip->len, server_ip->data, server_port, server->weight);
    status = string_copy(&pname, (uint8_t *)pname_buf, (uint32_t)(nc_strlen(pname_buf)));
    if (status != NC_OK) {
        return status;
    }

    /* if the address is the same, return */
    if (!string_compare(&server->pname, &pname)) {
        string_deinit(&pname);
        return NC_ERROR;
    }

    /* pname is no longer used, release it */
    string_deinit(&pname);

    /* change the server's address */
    status = server_set_address(server, server_ip, server_port);
    if (status != NC_OK) {
        return status;
    }

    /* Just set all conns done. If we close all connections in the
     * sentinel event and there are events for the connections which are
     * closed already, proxy will try to access the conns which are released.
     */
    server_conn_done(server);

    server_pool = server->owner;
    log_warn("success switch %.*s-%.*s to %.*s",
            server_pool->name.len, server_pool->name.data,
            server->name.len, server->name.data,
            server->pname.len, server->pname.data);

    return NC_OK;
}

static void
server_pool_sentinel_check(struct context *ctx, struct server_pool *pool)
{
    int64_t now;
    ASSERT(pool->redis);

    if (!array_n(&pool->sentinel)) {
        return;
    }

    if (pool->next_sentinel_connect == 0LL) {
        return;
    }

    now = nc_usec_now();
    if (now > 0 && now < pool->next_sentinel_connect) {
        return;
    }
    log_debug(LOG_NOTICE, "server_pool_sentinel_check reconnecting after disconnect for pool=%.*s", pool->name.len, pool->name.data);

    pool->sentinel_idx = (pool->sentinel_idx + 1) % array_n(&pool->sentinel);
    sentinel_connect(ctx, array_get_known_type(&pool->sentinel, pool->sentinel_idx, struct server));
}

static uint32_t
server_pool_hash(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    ASSERT(array_n(&pool->server) != 0);
    ASSERT(key != NULL);

    if (array_n(&pool->server) == 1) {
        return 0;
    }

    if (keylen == 0) {
        return 0;
    }

    return pool->key_hash((char *)key, keylen);
}

uint32_t
server_pool_idx(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    uint32_t hash, idx;
    uint32_t nservers = array_n(&pool->server);

    ASSERT(nservers != 0);
    ASSERT(key != NULL);

    if (nservers == 1) {
        /* Optimization: Skip hashing and dispatching for pools with only one server */
        return 0;
    }

    /*
     * If hash_tag: is configured for this server pool, we use the part of
     * the key within the hash tag as an input to the distributor. Otherwise
     * we use the full key
     */
    if (!string_empty(&pool->hash_tag)) {
        struct string *tag = &pool->hash_tag;
        uint8_t *tag_start, *tag_end;

        tag_start = nc_strchr(key, key + keylen, tag->data[0]);
        if (tag_start != NULL) {
            tag_end = nc_strchr(tag_start + 1, key + keylen, tag->data[1]);
            if ((tag_end != NULL) && (tag_end - tag_start > 1)) {
                key = tag_start + 1;
                keylen = (uint32_t)(tag_end - key);
            }
        }
    }

    switch (pool->dist_type) {
    case DIST_KETAMA:
        hash = server_pool_hash(pool, key, keylen);
        idx = ketama_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    case DIST_MODULA:
        hash = server_pool_hash(pool, key, keylen);
        idx = modula_dispatch(pool->continuum, pool->ncontinuum, hash);
        break;

    case DIST_RANDOM:
        idx = random_dispatch(pool->continuum, pool->ncontinuum, 0);
        break;

    default:
        NOT_REACHED();
        return 0;
    }
    ASSERT(idx < array_n(&pool->server));
    return idx;
}

static struct server *
server_pool_server(struct server_pool *pool, uint8_t *key, uint32_t keylen)
{
    struct server *server;
    uint32_t idx;

    idx = server_pool_idx(pool, key, keylen);
    server = array_get_known_type(&pool->server, idx, struct server);

    log_debug(LOG_VERB, "key '%.*s' on dist %d maps to server '%.*s'", keylen,
              key, pool->dist_type, server->pname.len, server->pname.data);

    return server;
}

/*
 * Returns a connection or null to forward the given key to. This will recursively choose a failover pool.
 */
static struct server *
server_pool_conn_failover(struct server_pool *failover, uint8_t *key,
                          uint32_t keylen)
{
    /* Fallback to the failover pool */
    struct server *server = NULL;

    if (failover == NULL) {
        return NULL;
    }

    server = server_pool_server(failover, key, keylen);
    if (server != NULL && server->fail == FAIL_STATUS_NORMAL) {
        log_debug(LOG_VERB, "fellback to failover connection to good server '%.*s' in pool '%.*s'",
                server->pname.len, server->pname.data, failover->name.len, failover->name.data);
        return server;
    } else if (server != NULL) {
        log_debug(LOG_VERB, "failed fallback to failover connection to dead server '%.*s' in pool '%.*s'",
                server->pname.len, server->pname.data, failover->name.len, failover->name.data);
    } else {
        log_debug(LOG_VERB, "failed fallback to failover connection, no server in pool '%.*s'",
                failover->name.len, failover->name.data);
    }
    // NOTE: If there is no failover pool,
    // then return the server so that nutcracker will automatically attempt to reconnect.
    if (failover->failover == NULL) {
        return server;
    }
    // Allow failover pools to have their own failover pools.
    // This may be useful for automatically switching pools when decommissioning servers.
    return server_pool_conn_failover(failover->failover, key, keylen);
}

/*
 * Choose the backend server to forward the request operating on the string key to.
 * This is called for every key in a memcache/redis request.
 */
struct conn *
server_pool_conn(struct context *ctx, struct server_pool *pool, uint8_t *key,
                 uint32_t keylen)
{
    rstatus_t status;
    struct server *server;
    struct conn *conn;

    server_pool_sentinel_check(ctx, pool);

    /* from a given {key, keylen} pick a server from pool */
    server = server_pool_server(pool, key, keylen);
    if (server == NULL || server->fail != FAIL_STATUS_NORMAL) {
        /* NOTE: Only attempt to choose a host in the failover pool if there is a failover pool. */
        if (pool->failover != NULL) {
            server = server_pool_conn_failover(pool->failover, key, keylen);
        }
    }

    if (server == NULL) {
        return NULL;
    }

    /* pick a connection to a given server */
    conn = server_conn(server);
    if (conn == NULL) {
        return NULL;
    }

    status = server_connect(ctx, server, conn);
    if (status != NC_OK) {
        server_close(ctx, conn);
        return NULL;
    }

    return conn;
}

static rstatus_t
server_pool_each_connect(void *elem, void *data)
{
    rstatus_t status;
    struct server_pool *sp = elem;

    if (array_n(&sp->sentinel)) {
        /* Try to connect the first sentinel. Proxy will try to reconnect
         * if it connects fail. So it's ok to ignore the return status.
         */
        sentinel_connect(sp->ctx, array_get_known_type(&sp->sentinel, 0, struct server));
    }

    if (!sp->preconnect) {
        return NC_OK;
    }

    status = array_each(&sp->server, server_each_preconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

rstatus_t
server_pool_connect(struct context *ctx)
{
    rstatus_t status;

    status = array_each(&ctx->pool, server_pool_each_connect, NULL);
    if (status != NC_OK) {
        return status;
    }

    return NC_OK;
}

static rstatus_t
server_pool_each_disconnect(void *elem, void *data)
{
    rstatus_t status;
    struct server_pool *sp = elem;

    status = array_each(&sp->server, server_each_disconnect, NULL);
    if (status != NC_OK) {
        return status;
    }

    if (array_n(&sp->sentinel)) {
        status = array_each(&sp->sentinel, server_each_disconnect, NULL);
        if (status != NC_OK) {
            return status;
        }
    }

    return NC_OK;
}

void
server_pool_disconnect(struct context *ctx)
{
    array_each(&ctx->pool, server_pool_each_disconnect, NULL);
}

static rstatus_t
server_pool_each_set_owner(void *elem, void *data)
{
    struct server_pool *sp = elem;
    struct context *ctx = data;

    sp->ctx = ctx;

    return NC_OK;
}

static rstatus_t
server_pool_each_calc_connections(void *elem, void *data)
{
    struct server_pool *sp = elem;
    struct context *ctx = data;

    ctx->max_nsconn += sp->server_connections * array_n(&sp->server);
    if (array_n(&sp->sentinel)) {
        /* only one sentinel conn at the same time */
        ctx->max_nsconn += 1;
    }
    ctx->max_nsconn += 1; /* pool listening socket */

    return NC_OK;
}

rstatus_t
server_pool_run(struct server_pool *pool)
{
    ASSERT(array_n(&pool->server) != 0);

    switch (pool->dist_type) {
    case DIST_KETAMA:
        return ketama_update(pool);

    case DIST_MODULA:
        return modula_update(pool);

    case DIST_RANDOM:
        return random_update(pool);

    default:
        NOT_REACHED();
        return NC_ERROR;
    }

    return NC_OK;
}

static rstatus_t
server_pool_each_run(void *elem, void *data)
{
    return server_pool_run(elem);
}

rstatus_t
server_pool_init(struct array *server_pool, struct array *conf_pool,
                 struct context *ctx)
{
    rstatus_t status;
    uint32_t npool;

    npool = array_n(conf_pool);
    ASSERT(npool != 0);
    ASSERT(array_n(server_pool) == 0);

    status = array_init(server_pool, npool, sizeof(struct server_pool));
    if (status != NC_OK) {
        return status;
    }

    /* transform conf pool to server pool */
    status = array_each(conf_pool, conf_pool_each_transform, server_pool);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }
    ASSERT(array_n(server_pool) == npool);

    /* set ctx as the server pool owner */
    status = array_each(server_pool, server_pool_each_set_owner, ctx);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    /* compute max server connections */
    ctx->max_nsconn = 0;
    status = array_each(server_pool, server_pool_each_calc_connections, ctx);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    /* set failover pool for each server pool */
    status = array_each(server_pool, server_pool_each_set_failover, server_pool);
    if (status != NC_OK) {
        log_error("server: failed to set failover pool");
        server_pool_deinit(server_pool);
        return status;
    }

    /* assert there are no infinite loops in failover pools */
    status = server_pool_validate_no_failover_loop(server_pool);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    /* update server pool continuum */
    status = array_each(server_pool, server_pool_each_run, NULL);
    if (status != NC_OK) {
        server_pool_deinit(server_pool);
        return status;
    }

    log_debug(LOG_DEBUG, "init %"PRIu32" pools", npool);

    return NC_OK;
}

void
server_pool_deinit(struct array *server_pool)
{
    uint32_t i, npool;

    for (i = 0, npool = array_n(server_pool); i < npool; i++) {
        struct server_pool *sp;

        sp = array_pop(server_pool);
        ASSERT(sp->p_conn == NULL);
        ASSERT(TAILQ_EMPTY(&sp->c_conn_q) && sp->nc_conn_q == 0);

        if (sp->continuum != NULL) {
            nc_free(sp->continuum);
            sp->ncontinuum = 0;
            sp->nserver_continuum = 0;
            sp->nlive_server = 0;
        }

        server_deinit(&sp->server);

        if (array_n(&sp->sentinel)) {
            server_deinit(&sp->sentinel);
        }

        log_debug(LOG_DEBUG, "deinit pool %"PRIu32" '%.*s'", sp->idx,
                  sp->name.len, sp->name.data);
    }

    array_deinit(server_pool);

    log_debug(LOG_DEBUG, "deinit %"PRIu32" pools", npool);
}

/* Get a message datastructure from the message pool to use to send a heartbeat - mark the connection as being in an error state if that was not done */
static struct msg *
heartbeat_msg_get(struct conn *conn)
{
    struct msg *msg;

    ASSERT(conn->client && !conn->proxy);

    msg = msg_get(conn, true, conn->redis);
    if (msg == NULL) {
        conn->err = errno;
    }

    return msg;
}

static uint32_t
set_heartbeat_command(struct mbuf *mbuf, int redis)
{
#define HEARTBEAT_MEMCACHE_COMMAND "get twemproxy\r\n"
#define HEARTBEAT_REDIS_COMMAND "*2\r\n$3\r\nget\r\n$9\r\ntwemproxy\r\n"
    char *command;
    uint32_t n;

    command = redis ? HEARTBEAT_REDIS_COMMAND : HEARTBEAT_MEMCACHE_COMMAND;
    n = (uint32_t)strlen(command);

    memcpy(mbuf->last, command, n);
    ASSERT((mbuf->last + n) <= mbuf->end);

    return n;
}

/* Send a heartbeat command to a backend server. See notes/heartbeat.md. */
/* Precondition: server->fail != FAIL_STATUS_NORMAL */
static rstatus_t
send_heartbeat(struct context *ctx, struct conn *conn, struct server *server)
{
    struct mbuf *mbuf;
    uint32_t n;
    struct msg *msg;
    struct server_pool *pool;
    struct conn *c_conn;
    rstatus_t status;

    if (conn->sent_heartbeat) {
        // Don't send more than one heartbeat over the same connection to a server.
        // - If there is a timeout waiting for the full response, this will reconnect.
        // - If it sends a response that is well-formed, the server will be marked as healthy
        // - If it sends a malformed response, the connection will be closed and treated as unhealthy.
        return NC_OK;
    }
    log_debug(LOG_INFO, "send heartbeat request to server sd %d of %.*s", conn->sd, server->name.len, server->name.data);
    conn->sent_heartbeat = 1;

    pool = (struct server_pool *)(server->owner);

    c_conn = conn_get(pool, true, conn->redis);
    if (c_conn == NULL) {
        return NC_ERROR;
    }

    /* Allocate a datastructure to send the heartbeat */
    msg = heartbeat_msg_get(c_conn);
    if (msg == NULL) {
        return NC_ERROR;
    }

    c_conn->rmsg = msg;
    mbuf = STAILQ_LAST(&msg->mhdr, mbuf, next);
    if (mbuf == NULL || mbuf_full(mbuf)) {
        mbuf = mbuf_get();
        if (mbuf == NULL) {
            return NC_ERROR;
        }
        mbuf_insert(&msg->mhdr, mbuf);
        msg->pos = mbuf->pos;
    }
    ASSERT(mbuf->end - mbuf->last > 0);

    /* Write the heartbeat request (an arbitrary read-only command) to the connection over an existing or new mbuf. */
    /* The request bytes are sent directly to the server backend and are not fragmented */
    n = set_heartbeat_command(mbuf, conn->redis);
    mbuf->last += n;
    msg->mlen += n;

    /* Heartbeats should not be sent to a client of nutcracker */
    msg->swallow = 1;
    msg->heartbeat = 1;
    server->fail = FAIL_STATUS_ERR_TRY_HEARTBEAT;

    if (TAILQ_EMPTY(&conn->imsg_q)) {
        /* If there are no events in progress then configure the event listeners to await a response (?) */
        status = event_add_out(ctx->evb, conn);
        if (status != NC_OK) {
            return status;
        }
    }
    conn->enqueue_inq(ctx, conn, msg);
    return NC_OK;
}

void
server_restore(struct context *ctx, struct conn *conn)
{
    struct server *server;

    server = (struct server *)(conn->owner);
    ASSERT(server != NULL);

    if (server->fail == FAIL_STATUS_NORMAL) {
        return;
    }
    ASSERT(!server->sentinel);

    /* If the server's in an error state: On adding a server back into the pool send a heartbeat command to check if it is still healthy and should still be in the pool (?) */
    if (send_heartbeat(ctx, conn, server) != NC_OK) {
        log_error("Unexpectedly failed to send a heartbeat to the server to attempt reconnection");
    }
}

rstatus_t
server_reconnect(struct context *ctx, struct server *server)
{
    rstatus_t status;
    struct conn *conn;

    conn = server_conn(server);
    if (conn == NULL) {
        return NC_ERROR;
    }

    status = server_connect(ctx, server, conn);
    if (status == NC_OK) {
        if (conn->connected) {
            conn->restore(ctx, conn);
        }
    } else {
        server_close(ctx, conn);
    }

    return status;
}

void
add_failed_server(struct context *ctx, struct server *server)
{
    struct server **pserver;

    server->fail = FAIL_STATUS_ERR_TRY_CONNECT;
    for (uint32_t i = 0; i < array_n(ctx->fails); i++) {
        struct server *other = *(struct server **)array_get(ctx->fails, i);
        if (other == server) {
            log_debug(LOG_INFO, "Filtering out redundant attempt to reconnect to server %.*s in pool %.*s",
                    server->name.len, server->name.data, server->owner->name.len, server->owner->name.data);
            /* Don't add a server to fails if it's already in the array */
            return;
        }
    }
    pserver = (struct server **)array_push(ctx->fails);
    *pserver = server;
}

/* Called when a response to a heartbeat command is received. See notes/heartbeat.md. */
void
server_restore_from_heartbeat(struct server *server, struct conn *conn)
{
    struct server_pool *pool;
    rstatus_t status;

    conn->unref(conn);
    conn_put(conn);
    pool = (struct server_pool *)server->owner;
    /* Indicate that the failover pool should no longer be used for this server */
    server->fail = FAIL_STATUS_NORMAL;

    /* Update the pool of backend hosts to reintroduce this server now that it's healthy */
    status = server_pool_run(pool);
    if (status == NC_OK) {
        log_debug(LOG_NOTICE, "updating pool %"PRIu32" '%.*s',"
                "restored server '%.*s'", pool->idx,
                pool->name.len, pool->name.data,
                server->name.len, server->name.data);
    } else {
        log_error("updating pool %"PRIu32" '%.*s' failed: %s", pool->idx,
                pool->name.len, pool->name.data, strerror(errno));
    }
}
