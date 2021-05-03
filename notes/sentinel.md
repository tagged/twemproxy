Redis Sentinel
==============

Most of the implementation is from https://github.com/twitter/twemproxy/pull/324

The design is described in https://github.com/twitter/twemproxy/issues/297

> It makes twemproxy work with redis-sentinel to auto detect redis instance failover, and change its forward address.
>
> The design of the patch is shown below.
>
> 1. configure sentinels in configuration like servers.
>    Sentinel address can be configured one or more like servers. Twemproxy pick one, and connect.
> 2. fetch redis addresses and maintain it consistency with sentinel
>
>    twemproxy will send info sentinel and subscribe requests to sentinel when it connects to sentinel.
>    twemproxy update servers’s addresses from info sentinel response, and fetch redis failover event from subscribe channel. So twemproxy can maintain the consistency of redis addresses with redis-sentinel.
> 3. sentinel reconnect
>
>    Twemproxy will pick an sentinel to reconnect When sentinel connection is done.
>    A different sentinel will be picked if multiple sentinels are configured. So twemproxy can switch to a good sentinel when some sentinels are done.
>    Twemproxy will send info sentinel and subscribe requests to sentinel when the new connection is established, just like it connect to sentinel at the first time.
>    (keepalive will be used)
> 4. Identify the same redis between proxy and sentinel
>
> We configure the servername in the proxy as same as the master-name configured in sentinel. The servername is the redis identification between proxy and sentinel.
> For example, configuration in proxy:
>
> ```
> servers:
>  - 127.0.0.1:6379:1 server1
> ```
>
> configuration in sentinel:
>
> ```
> sentinel monitor server1 127.0.0.1 6379 2
> ```
>
> 1. some small feature
>    **Twemproxy will dump a new configuration when it changes the redis address.** It can let user know the status in the proxy and avoid some problem when proxy is restarted.
>
> That's design of the patch. I’m glad to hear your advices about the patch.


Sentinel reconnection logic is different from redis reconnection logic. The heartbeat and failover patches don't affect sentinels, even when a sentinel disconnects.

Note that configs will only be rewritten in response to an event from a redis sentinel, so if redis is not used or redis is used without sentinels are configured, then the config would not be rewritten.

Config rewriting is done by saving to a temporary file and then renaming the temporary file to the original file atomically.
