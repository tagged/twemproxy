Failover patches
================

The failover patches depend on the [heartbeat patches](./heartbeat.md)

The failover patches allow sending requests to another pool if
a good server isn't available in the original pool.  This provides an alternate
means for replacing cache servers to ejecting them from the continuum, useful
when cache objects have long lifetimes that are vulnerable to stale data.

**This should only be used with `auto_eject_hosts: false`** to avoid caching stale data
and to ensure the failover pool is actually used.

This changes the interpretation of `auto_eject_hosts` to mean just whether failed
hosts are ejected from the continuum or not, but allow heartbeat and reconnect
handling to be done.

Failover patches are recursive - a failover pool can have its own failover pool,
as long as there are no cycles (checked during startup).

This is set by adding `failover: failover_pool_name` to the config section for a pool


Key sharding changes
--------------------

When a memcache pool does not have failover: If a client sends `get a b c d e f` to twemproxy, and a b c are in one server of the `main` pool using `failover`, then nutcracker will attempt to send `get a b c` to the chosen server of the `main` pool based on the first key in that command. If there was a failover pool, this would be incorrect - if the chosen server is marked as down, then a server in the failover pool would be chosen based on `hash(a)` - but that's probably different from the server chosen for `hash(b)` or `hash(c)` (unless the failover pool was deliberately given the exact same labels, which is unlikely)

To work around this, memcache multigets will deliberately split up into multiple gets with a single key each, so that all keys are sent to the correct failover pool.

For redis, it's strongly recommended to use the `build-nutredis` branch instead, which supports redis-sentinel and redis's native failover mechanism.
