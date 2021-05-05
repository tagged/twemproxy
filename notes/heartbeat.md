Heartbeat Patches
=================

These apply to all server groups that use ketama when they set `auto_eject_hosts: true`.
These are unconditionally enabled.

Server status
-------------

A server(`struct server`, a single connection to single server backend) can be in one of three states:

1. `FAIL_STATUS_NORMAL`(0): The server is healthy
2. `FAIL_STATUS_TRY_CONNECT`(1): The server has failed and twemproxy will asynchronously send a heartbeat later on.

   All incoming and outgoing responses and requests are removed from the server before putting it into this state(`server_failure`).
3. `FAIL_STATUS_TRY_HEARTBEAT`(2): The server is in the process of connecting and sending a heartbeat to determine if the server has recovered.

This is different from the pre-heartbeat implementation, where the ability to reconnect was determined by whether `server->next_retry` had elapsed (based on the time when the server failed plus `server_retry_timeout`).
In the pre-heartbeat implementation, servers would be reintroduced into the pool once that timeout had elapsed. See notes/recommendation.md for outdated documentation.


The heartbeat is a memcache/redis get command which is marked as `swallow` so that nutcracker does not attempt to forward the response to a placeholder client (`send_heartbeat`).
If the server sends a well-formed non-error response, the server's status goes back to `FAIL_STATUS_NORMAL` in `server_restore_from_heartbeat`

Failed server lists
-------------------

See `retry_connection`, which is specific to the heartbeat patch.
This is called in response to events or timeouts (the stats computation timeout interval is 30 seconds), even events such as requests/responses for a different pool.

The heartbeat patch alternates between two variable-sized `array`s of failed servers to ensure that in any loop over servers, a failing server is processed at most once.
Those will call `server_reconnect` to begin the process of connecting and sending a heartbeat to check if the server is healthy after the reconnect.

- If/when reconnection or the heartbeat fails, it gets added to the `ctx->failed_servers` list at the opposite index to retry again.

Bugs
----

When `auto_eject_hosts` is false, it seems like the heartbeat is sent redundantly and isn't sent ahead of time.

- The heartbeat message gets sent more than once over the same connection if pipelined requests trigger the reconnect.
- The heartbeat message gets sent after the requests get sent.
- However, if a failover pool is configured, then it works correctly - the heartbeat does get sent to the remote server at the configured `server_retry_timeout`, and until the heartbeat passes, the

(this is different from `auto_eject_hosts: true`, where heartbeats get triggered by attempts to reintroduce a host to the pool)

If a pool is timing out or rejecting connections, new connection attempts triggered by proxied attempts will still be made and timeout.

It may be possible to improve that and immediately reject requests for hosts that are in a known bad state for multiple retries

TODOs
-----

Add an additional timer for more consistent `server_retry_timeout` behavior on the main pool. Note that memcached requests and responses on any pool will also trigger an event leading to the heartbeat code attempting to reconnect to failed servers, so this only matters when there is a low volume of requests.
The stats timeout is 30000 and currently also triggers automatic reconnect attempts as a side effect when there are no other events.
