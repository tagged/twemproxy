#include <nc_core.h>
#include <nc_conf.h>
#include <nc_sentinel.h>

static char *sentinel_reqs[] = {
    INFO_SENTINEL,
    SUB_SWITCH_REDIRECT
};

struct conn *
sentinel_conn(struct server *sentinel)
{
    struct conn *conn;

    /* sentinel has only one connection */
    if (sentinel->ns_conn_q == 0) {
        return conn_get(sentinel, false, true);
    }
    ASSERT(sentinel->ns_conn_q == 1);

    conn = TAILQ_FIRST(&sentinel->s_conn_q);
    ASSERT(!conn->client && !conn->proxy);
    ASSERT(conn->status == CONN_DISCONNECTED);

    return conn;
}

static void
sentinel_set_next_connect(struct server_pool *pool)
{
    int64_t now;

    now = nc_usec_now();
    if (now < 0) {
        /* get time failed, we reconnect immediately */
        pool->next_sentinel_connect = 1LL;
        return;
    }

    pool->next_sentinel_connect = now + pool->server_retry_timeout;
}

rstatus_t
sentinel_connect(struct context *ctx, struct server *sentinel)
{
    rstatus_t status;
    struct conn *conn;
    struct msg *msg;
    int cmd_num;
    int i;

    ASSERT(sentinel->sentinel);

    /* get the only connect of sentinel */
    conn = sentinel_conn(sentinel);
    if (conn == NULL) {
        /* can't call sentinel_close, manual set next connect */
        sentinel_set_next_connect(sentinel->owner);
        return NC_ENOMEM;
    }

    status = server_connect(ctx, sentinel, conn);
    if(status != NC_OK) {
        sentinel_close(ctx, conn);
        return status;
    }

    /* set keepalive opt on sentinel socket to detect socket dead */
    status = nc_set_tcpkeepalive(conn->sd, SENTINEL_KEEP_INTERVAL);
    if (status < 0) {
        log_error("set keepalive on s %d for sentienl server failed: %s",
                  conn->sd, strerror(errno));
        sentinel_close(ctx, conn);
        return status;
    }

    cmd_num = sizeof(sentinel_reqs) / sizeof(char *);
    for (i = 0; i < cmd_num; i++) {
        msg = req_fake(ctx, conn);
        if(msg == NULL) {
            conn->err = errno;
            sentinel_close(ctx, conn);
            return NC_ENOMEM;
        }

        status = msg_append(msg, (uint8_t *)(sentinel_reqs[i]), nc_strlen(sentinel_reqs[i]));
        if (status != NC_OK) {
            conn->err = errno;
            sentinel_close(ctx, conn);
            return status;
        }
    }

    conn->status = CONN_SEND_REQ;

    sentinel->owner->next_sentinel_connect = 0LL;

    return NC_OK;
}

void
sentinel_close(struct context *ctx, struct conn *conn)
{
    struct server_pool *pool;

    pool = ((struct server*)conn->owner)->owner;

    sentinel_set_next_connect(pool);

    conn->status = CONN_DISCONNECTED;

    server_close(ctx, conn);
}

/* Returns true if the expected prefix and sep byte was parsed from line_buf into tmp_string */
static bool
parse_expected_key_from_mbuf(struct mbuf *line_buf, const char sep, const struct string *expected_prefix, struct string *tmp_string)
{
    // tmp_string is already initialized. It will be modified by this function.
    // If the result is NC_OK, it will have the same contents as expected_prefix
    rstatus_t status;
    status = mbuf_read_string(line_buf, '=', tmp_string);
    if (status != NC_OK) {
        log_error("skip server %s%c prefix failed.", expected_prefix->data, sep);
        return false;
    }
    if (!string_has_prefix(tmp_string, expected_prefix)) {
        log_error("Expected %s%c", expected_prefix->data, sep);
        return false;
    }
    return true;
}

static rstatus_t
sentinel_proc_sentinel_info(struct context *ctx, struct server *sentinel, struct msg *msg)
{
    rstatus_t status;
    /* XXX parsing assumes sentinel masters response is before the sentinel data, which is currently true */
    int i, master_num = 0, switch_num, server_port;
    struct string server_name;
    struct string server_ip;
    struct string const_sentinel_masters_prefix;
    struct string const_sentinel_key_prefix;
    struct string const_master_prefix;
    struct string const_server_key;
    struct string const_name_key;
    struct string const_address_key;
    struct string const_status_key;

    struct string tmp_string;
    struct string tmp_value;
    struct server *server;
    struct mbuf *line_buf;
    int lines_with_master_count = 0;

    string_init(&tmp_string);
    string_init(&tmp_value);
    string_init(&server_name);
    string_init(&server_ip);
    string_set_text(&const_sentinel_masters_prefix, "sentinel_masters");
    string_set_text(&const_sentinel_key_prefix, "sentinel_");
    string_set_text(&const_master_prefix, "master");
    string_set_text(&const_name_key, "name");
    string_set_text(&const_address_key, "address");
    string_set_text(&const_status_key, "status");

    /*
     * Example output to parse (number of lines with "sentinel_" vary with the version. All lines end in \r\n)
     *
     * $946
     * # Sentinel
     * sentinel_masters:10
     * sentinel_tilt:0
     * sentinel_running_scripts:0
     * sentinel_scripts_queue_length:0
     * sentinel_simulate_failure_flags:0
     * master0:name=my_db001,status=ok,address=10.155.155.5:6380,slaves=1,sentinels=3
     * master1:name=my_db004,status=ok,address=10.155.155.5:6383,slaves=1,sentinels=3
     * master2:name=my_db005,status=ok,address=10.155.155.5:6384,slaves=1,sentinels=3
     * master3:name=my_db003,status=ok,address=10.155.155.6:6382,slaves=1,sentinels=3
     * master4:name=my_db002,status=ok,address=10.155.155.5:6381,slaves=1,sentinels=3
     * master5:name=my_db006,status=ok,address=10.155.155.5:6385,slaves=1,sentinels=3
     * master6:name=my_db009,status=ok,address=10.155.155.5:6388,slaves=1,sentinels=3
     * master7:name=my_db000,status=ok,address=10.155.155.5:6379,slaves=1,sentinels=3
     * master8:name=my_db008,status=ok,address=10.155.155.5:6387,slaves=1,sentinels=3
     * master9:name=my_db007,status=ok,address=10.155.155.5:6386,slaves=1,sentinels=3
     */
    line_buf = mbuf_get();
    if (line_buf == NULL) {
        goto error;
    }

    /* get sentinel master num at line 3 */
    /* Assume the first two lines are "$[len]" and "# Sentinel" */
    msg_read_line(msg, line_buf, 2);
    if (mbuf_length(line_buf) == 0) {
        log_error("read first two lines failed from sentinel ack info when skip line not used.");
        goto error;
    }
    while (1) {
        /* read a single line, starting from line 3 */
        msg_read_line(msg, line_buf, 1);
        if (mbuf_length(line_buf) == 0) {
            if (master_num == 0 && lines_with_master_count == 1) {
                break;
            }
            log_error("read third lines failed from sentinel ack info when skip line not used.");
            goto error;
        }
        /* First, verify the line is of the form "key:value" */
        status = mbuf_read_string(line_buf, ':', &tmp_string);
        /* TODO: handle 0 masters? */
        if (status != NC_OK) {
            goto error;
        }
        if (string_has_prefix(&tmp_string, &const_master_prefix)) {
            if (lines_with_master_count != 1) {
                log_error("Saw a key for a master before seeing a line with sentinel_masters");
                goto error;
            }
            if (master_num == 0) {
                log_error("Saw info for a master, but also saw sentinel_masters:0");
                goto error;
            }

            /* parse master info from sentinel ack info */
            /* E.g. "master0:name=my_db001,status=ok,address=10.155.155.5:6380,slaves=1,sentinels=3" */
            switch_num = 0;
            for (i = 0; i < master_num; i++) {
                /* For the first line, we read everything up to the ':' already */
                if (i > 0) {
                    msg_read_line(msg, line_buf, 1);
                    if (mbuf_length(line_buf) == 0) {
                        log_error("read line failed from sentinel ack info when parse master item.");
                        goto error;
                    }

                    /* skip master item server name prefix */
                    /* master0:name=my_db001,status=ok,address=10.155.155.5:6380,slaves=1,sentinels=3" */
                    /* ^^^^^^^ */
                    status = mbuf_read_string(line_buf, ':', NULL);
                    if (status != NC_OK) {
                        log_error("skip server name prefix failed.");
                        goto error;
                    }
                }

                /* skip master item server name prefix */
                /* master0:name=my_db001,status=ok,address=10.155.155.5:6380,slaves=1,sentinels=3" */
                /*         ^^^^ */
                if (!parse_expected_key_from_mbuf(line_buf, '=', &const_name_key, &tmp_string)) {
                    goto error;
                }

                /* get server name */
                /* master0:name=my_db001,status=ok,address=10.155.155.5:6380,slaves=1,sentinels=3" */
                /*              ^^^^ */
                status = mbuf_read_string(line_buf, ',', &server_name);
                if (status != NC_OK) {
                    log_error("get server name failed.");
                    goto error;
                }

                server = server_find_by_name(ctx, sentinel->owner, &server_name);
                if (server == NULL) {
                    log_error("unknown server name:%.*s", server_name.len, server_name.data);
                    goto error;
                }

                /* skip master status */
                /* master0:name=my_db001,status=ok,address=10.155.155.5:6380,slaves=1,sentinels=3" */
                /*                       ^^^^^^ */
                if (!parse_expected_key_from_mbuf(line_buf, '=', &const_status_key, &tmp_string)) {
                    goto error;
                }
                /* master0:name=my_db001,status=ok,address=10.155.155.5:6380,slaves=1,sentinels=3" */
                /*                              ^^ */
                status = mbuf_read_string(line_buf, ',', NULL);
                if (status != NC_OK) {
                    log_error("get master status failed.");
                    goto error;
                }

                /* skip ip string prefix name */
                /* master0:name=my_db001,status=ok,address=10.155.155.5:6380,slaves=1,sentinels=3" */
                /*                                 ^^^^^^^ */
                if (!parse_expected_key_from_mbuf(line_buf, '=', &const_address_key, &tmp_string)) {
                    goto error;
                }

                /* get server ip string */
                /* master0:name=my_db001,status=ok,address=10.155.155.5:6380,slaves=1,sentinels=3" */
                /*                                         ^^^^^^^^^^^^ */
                status = mbuf_read_string(line_buf, ':', &server_ip);
                if (status != NC_OK) {
                    log_error("get server ip string failed.");
                    goto error;
                }

                /* get server port */
                /* master0:name=my_db001,status=ok,address=10.155.155.5:6380,slaves=1,sentinels=3" */
                /*                                                      ^^^^ */
                status = mbuf_read_string(line_buf, ',', &tmp_string);
                if (status != NC_OK) {
                    log_error("get server port string failed.");
                    goto error;
                }
                server_port = nc_atoi(tmp_string.data, tmp_string.len);
                if (server_port < 0) {
                    log_error("translate server port string to int failed.");
                    goto error;
                }
                /* Ignore the ,slaves=%d,sentinels=%d field of INFO */

                status = server_switch(ctx, server, &server_ip, server_port);
                /* if server is switched, add switch number */
                if (status == NC_OK) {
                    switch_num++;
                }
            }

            if (switch_num > 0) {
                conf_rewrite(ctx);
            }

            status = NC_OK;
            goto done;
        }
        // Parse everything after the ':' to the first '\r' (The value of the key-value pair)
        status = mbuf_read_string(line_buf, CR, &tmp_value);
        if (status != NC_OK) {
            goto error;
        }
        if (!string_has_prefix(&tmp_string, &const_sentinel_key_prefix)) {
            /* check against "master" */
            log_warn("Found line in \"sentinel info\" output not beginning with \"sentinel_\" or \"master\", skipping");
            continue;
        } else {
            if (string_has_prefix(&tmp_string, &const_sentinel_masters_prefix)) {
                if (lines_with_master_count != 0) {
                    log_error("Found multiple \"sentinel_masters:\" lines");
                    goto error;
                }
                lines_with_master_count++;

                // Read the number from tmp_value, from a line such as "sentinel_masters:10"
                master_num = nc_atoi(tmp_value.data, tmp_value.len);
                if (master_num < 0) {
                    log_error("parse master number from sentinel ack info failed.");
                    goto error;
                }
            }
        }
    }
    if (lines_with_master_count == 0) {
        log_error("Did not find line in \"sentinel info\" output with key \"sentinel_masters\"");
        goto error;
    }
    goto done;

done:
    if (line_buf != NULL) {
        mbuf_put(line_buf);
    }
    string_deinit(&tmp_string);
    string_deinit(&tmp_value);
    string_deinit(&server_name);
    string_deinit(&server_ip);
    return status;

error:
    status = NC_ERROR;
    goto done;
}

static rstatus_t
sentinel_proc_acksub(struct context *ctx, struct msg *msg, struct string *sub_channel)
{
    rstatus_t status;
    struct string sub_titile, tmp_string;
    struct mbuf *line_buf;

    string_init(&tmp_string);
    string_set_text(&sub_titile, "subscribe");

    line_buf = mbuf_get();
    if (line_buf == NULL) {
        goto error;
    }

    /* get line in line num 3  for sub titile */
    msg_read_line(msg, line_buf, 3);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel ack sub when skip line not used.");
        goto error;
    }
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK || string_compare(&sub_titile, &tmp_string)) {
        goto error;
    }

    /* get line in line num 5  for sub channel */
    msg_read_line(msg, line_buf, 2);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel ack sub when skip line not used.");
        goto error;
    }
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK || string_compare(sub_channel, &tmp_string)) {
        goto error;
    }

    log_debug(LOG_INFO, "success sub channel %.*s from sentinel", sub_channel->len, sub_channel->data);

    status = NC_OK;

done:
    if (line_buf != NULL) {
        mbuf_put(line_buf);
    }
    string_deinit(&tmp_string);
    return status;

error:
    status = NC_ERROR;
    goto done;
}

static rstatus_t
sentinel_proc_pub(struct context *ctx, struct server *sentinel, struct msg *msg)
{
    rstatus_t status;
    int server_port;
    struct string server_name, server_ip, tmp_string, pub_titile;
    struct mbuf *line_buf;
    struct server *server;

    string_init(&tmp_string);
    string_init(&server_name);
    string_init(&server_ip);

    string_set_text(&pub_titile, "message");

    line_buf = mbuf_get();
    if (line_buf == NULL) {
        goto error;
    }

    /* get line in line num 3  for pub titile */
    msg_read_line(msg, line_buf, 3);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel pmessage when skip line not used.");
        msg_dump(msg, LOG_INFO);
        goto error;
    }
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK || string_compare(&pub_titile, &tmp_string)) {
        log_error("pub title error(line info %.*s)", tmp_string.len, tmp_string.data);
        goto error;
    }

    /* get line in line num 7 for pub info */
    msg_read_line(msg, line_buf, 4);
    if (mbuf_length(line_buf) == 0) {
        log_error("read line failed from sentinel pmessage when skip line not used.");
        goto error;
    }

    /* get server */
    status = mbuf_read_string(line_buf, ' ', &server_name);
    if (status != NC_OK) {
        log_error("get server name string failed.");
        goto error;
    }
    server = server_find_by_name(ctx, sentinel->owner, &server_name);
    if (server == NULL) {
        log_error("unknown server name:%.*s", server_name.len, server_name.data);
        goto error;
    }

    /* skip old ip and port string */
    status = mbuf_read_string(line_buf, ' ', NULL);
    if (status != NC_OK) {
        log_error("skip old ip string failed.");
        goto error;
    }
    status = mbuf_read_string(line_buf, ' ', NULL);
    if (status != NC_OK) {
        log_error("skip old port string failed.");
        goto error;
    }

    /* get new server ip string */
    status = mbuf_read_string(line_buf, ' ', &server_ip);
    if (status != NC_OK) {
        log_error("get new server ip string failed.");
        goto error;
    }

    /* get new server port */
    status = mbuf_read_string(line_buf, CR, &tmp_string);
    if (status != NC_OK) {
        log_error("get new server port string failed.");
        goto error;
    }
    server_port = nc_atoi(tmp_string.data, tmp_string.len);
    if (server_port < 0) {
        log_error("tanslate server port string to int failed.");
        goto error;
    }

    status = server_switch(ctx, server, &server_ip, server_port);
    ASSERT(status == NC_OK);
    conf_rewrite(ctx);

    status = NC_OK;

done:
    if (line_buf != NULL) {
        mbuf_put(line_buf);
    }
    string_deinit(&tmp_string);
    string_deinit(&server_ip);
    string_deinit(&server_name);
    return status;

error:
    status = NC_ERROR;
    goto done;
}

void
sentinel_recv_done(struct context *ctx, struct conn *conn, struct msg *msg,
              struct msg *nmsg)
{
    rstatus_t status;
    struct string sub_channel;

    ASSERT(!conn->client && !conn->proxy);
    ASSERT(msg != NULL && conn->rmsg == msg);
    ASSERT(!msg->request);
    ASSERT(msg->owner == conn);
    ASSERT(nmsg == NULL || !nmsg->request);
    ASSERT(conn->status != CONN_DISCONNECTED);

    // TODO: Figure out why there are empty sentinel messages.
    // When there are empty sentinel messages, nutcracker will mark the sentinel as being in an error state and close the connection.
    // (This may be deliberate, filtering out empty messages results in test failures)
    /*
    if (msg_empty(msg)) {
        log_debug(LOG_VERB, "saw empty rsp %"PRIu64" on sentinel %d", msg->id,
                  conn->sd);
        // rsp_put(msg);
        // return true;
    }
    */

    /* enqueue next message (response), if any */
    conn->rmsg = nmsg;

    switch (conn->status) {
    case CONN_SEND_REQ:
        status = sentinel_proc_sentinel_info(ctx, conn->owner, msg);
        if (status == NC_OK) {
            conn->status = CONN_ACK_INFO;
        }
        break;

    case CONN_ACK_INFO:
        string_set_text(&sub_channel, SENTINEL_SWITCH_CHANNEL);
        status = sentinel_proc_acksub(ctx, msg, &sub_channel);
        if (status == NC_OK) {
            conn->status = CONN_ACK_SWITCH_SUB;
        }
        break;

    case CONN_ACK_SWITCH_SUB:
        string_set_text(&sub_channel, SENTINEL_REDIRECT_CHANNEL);
        status = sentinel_proc_acksub(ctx, msg, &sub_channel);
        if (status == NC_OK) {
            conn->status = CONN_ACK_REDIRECT_SUB;
        }
        break;

    case CONN_ACK_REDIRECT_SUB:
        status = sentinel_proc_pub(ctx, conn->owner, msg);
        break;

    default:
        status = NC_ERROR;
    }

    rsp_put(msg);

    if (status != NC_OK) {
        log_error("sentinel's response error, close sentinel conn.");
        conn->done = 1;
    }
}
