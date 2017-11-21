# redis-migrate-tool

**redis-migrate-tool** is a convenient and useful tool for migrating data between [redis](https://github.com/antirez/redis). 

## [中文介绍](http://www.oschina.net/p/redis-migrate-tool)

## Features

+ Fast.
+ Multi-Threads.
+ Based on redis replication.
+ Live migration.
+ In the process of migrating data, the source redis can also provide services for users.
+ Heterogeneous migration.
+ Twemproxy and redis cluster support.
+ When the target is twemproxy, keys are direct imported into redis behind the twemproxy.
+ Migration Status view.
+ Data Verification Mechanism.

## Dependence

Please install automake, libtool, autoconf and bzip2 at first.

## Build

To build redis-migrate-tool:

    $ cd redis-migrate-tool
    $ autoreconf -fvi
	$ ./configure
    $ make
    $ src/redis-migrate-tool -h

## RUN

    src/redis-migrate-tool -c rmt.conf -o log -d
	
## WARNING

Before run this tool, make sure your source redis machines have enough memory allowed at least one redis generate rdb file.

If your source machines have large enough memory allowed all the redis generate rdb files at one time, you can set 'source_safe: false' in the rmt.conf.

## Not supported redis command

The following commands are not supported to be propagated to the target redis group, because the keys in those commands maybe cross different target redis nodes:

RENAME,RENAMENX,RPOPLPUSH,BRPOPLPUSH,FLUSHALL,FLUSHDB,BITOP,MOVE,GEORADIUS,GEORADIUSBYMEMBER,EVAL,EVALSHA,SCRIPT,PFMERGE

## Configuration

Config file has three parts: source, target and common.

### source OR target:

+ **type**: The group redis type. Possible values are:
 + single
 + twemproxy
 + redis cluster
 + rdb file
 + aof file
+ **servers:**: The list of redis address in the group. If type is twemproxy, this is same as the twemproxy config file. If type is rdb file, this is the file name.
+ **redis_auth**: Authenticate to the Redis server on connect.
+ **timeout**: Timeout in milliseconds for read/write with Redis server. Now just for source redis group. Defaults to 120000.
+ **hash**: The name of the hash function. Just for type is twemproxy. Possible values are:
 + one_at_a_time
 + md5
 + crc16
 + crc32 (crc32 implementation compatible with [libmemcached](http://libmemcached.org/))
 + crc32a (correct crc32 implementation as per the spec)
 + fnv1_64
 + fnv1a_64
 + fnv1_32
 + fnv1a_32
 + hsieh
 + murmur
 + jenkins
+ **hash_tag**: A two character string that specifies the part of the key used for hashing. Eg "{}" or "$$". [Hash tag](notes/recommendation.md#hash-tags) enable mapping different keys to the same server as long as the part of the key within the tag is the same. Just for type is twemproxy.
+ **distribution**: The key distribution mode. Just for type is twemproxy. Possible values are:
 + ketama
 + modula
 + random

### common:
+ **listen**: The listening address and port (name:port or ip:port). Defaults to 127.0.0.1:8888.
+ **max_clients**: The max clients count for the listen port. Defaults to 100.
+ **threads**: The max threads count can be used by redis-migrate-tool. Defaults to the cpu core count.
+ **step**: The step for parse request. The higher the number, the more quickly to migrate, but the more memory used. Defaults to 1.
+ **mbuf_size**: Mbuf size for request. Defaults to 512.
+ **noreply**: A boolean value that decide whether to check the target group replies. Defaults to false.
+ **source_safe**: A boolean value that protect the source group machines memory safe. If it is true, the tool can guarantee only one redis to generate rdb file at one time on the same machine for source group. In addition, 'source_safe: true' may use less threads then you set. Defaults to true.
+ **dir**: Work directory, used to store files(such as rdb file). Defaults to the current directory.
+ **filter**: Filter keys if they do not match the pattern. The pattern is Glob-style. Defaults is NULL.


**filter** supported glob-style patterns:

+ h?llo matches hello, hallo and hxllo

+ h*llo matches hllo and heeeello

+ h[ae]llo matches hello and hallo, but not hillo

+ h[^e]llo matches hallo, hbllo, ... but not hello

+ h[a-b]llo matches hallo and hbllo


Use \ to escape special characters if you want to match them verbatim.

For example, the configuration file shown below is to migrate data from single to twemproxy.

    [source]
    type: single
    servers:
     - 127.0.0.1:6379
     - 127.0.0.1:6380
     - 127.0.0.1:6381
     - 127.0.0.1:6382

    [target]
    type: twemproxy
    hash: fnv1a_64
    hash_tag: "{}"
    distribution: ketama
    servers:
     - 127.0.0.1:6380:1 server1
     - 127.0.0.1:6381:1 server2
     - 127.0.0.1:6382:1 server3
     - 127.0.0.1:6383:1 server4
	
    [common]
    listen: 0.0.0.0:8888
    threads: 2
    step: 1
    mbuf_size: 1024
    source_safe: true


Migrate data from twemproxy to redis cluster.

    [source]
    type: twemproxy
    hash: fnv1a_64
    hash_tag: "{}"
    distribution: ketama
    servers:
     - 127.0.0.1:6379
     - 127.0.0.1:6380
     - 127.0.0.1:6381
     - 127.0.0.1:6382

    [target]
    type: redis cluster
    servers:
     - 127.0.0.1:7379
	
    [common]
    listen: 0.0.0.0:8888
    step: 1
    mbuf_size: 512
    
Migrate data from a redis cluster to another redis cluster with key filter(key's prefix is "abc").

    [source]
    type: redis cluster
    servers:
     - 127.0.0.1:8379

    [target]
    type: redis cluster
    servers:
     - 127.0.0.1:7379
	
    [common]
    listen: 0.0.0.0:8888
    filter: abc*
	
Load data from rdb file to redis cluster.

    [source]
    type: rdb file
    servers:
     - /data/redis/dump1.rdb
	 - /data/redis/dump2.rdb
	
    [target]
    type: redis cluster
    servers:
     - 127.0.0.1:7379
	
    [common]
    listen: 0.0.0.0:8888
    step: 2
    mbuf_size: 512
    source_safe: false
    
Just save rdb file from redis cluster.

    [source]
    type: redis cluster
    servers:
     - 127.0.0.1:7379
	
    [target]
    type: rdb file
	
    [common]
    listen: 0.0.0.0:8888
    source_safe: true
    
Load data from aof file to redis cluster.

    [source]
    type: aof file
    servers:
     - /data/redis/appendonly1.aof
     - /data/redis/appendonly2.aof
	
    [target]
    type: redis cluster
    servers:
     - 127.0.0.1:7379
	
    [common]
    listen: 0.0.0.0:8888
    step: 2

## STATUS

You can use redis-cli to connect with redis-migrate-tool. The listening address and port can be setted at common config.

### info command

For example, you try the **info** command:
	
    $redis-cli -h 127.0.0.1 -p 8888
    127.0.0.1:8888> info
    # Server
    version:0.1.0
    os:Linux 2.6.32-573.12.1.el6.x86_64 x86_64
    multiplexing_api:epoll
    gcc_version:4.4.7
    process_id:9199
    tcp_port:8888
    uptime_in_seconds:1662
    uptime_in_days:0
    config_file:/ect/rmt.conf
	
    # Clients
    connected_clients:1
    max_clients_limit:100
    total_connections_received:3
	
    # Memory
    mem_allocator:jemalloc-4.0.4
	
    # Group
    source_nodes_count:32
    target_nodes_count:48
	
    # Stats
    all_rdb_received:1
    all_rdb_parsed:1
    all_aof_loaded:0
    rdb_received_count:32
    rdb_parsed_count:32
    aof_loaded_count:0
    total_msgs_recv:7753587
    total_msgs_sent:7753587
    total_net_input_bytes:234636318
    total_net_output_bytes:255384129
    total_net_input_bytes_human:223.77M
    total_net_output_bytes_human:243.55M
    total_mbufs_inqueue:0
    total_msgs_outqueue:0
    127.0.0.1:8888>
	
**info** command response instruction:
	
#### Server:

+ **version**: The redis-migrate-tool version number.
+ **os**: The os uname.
+ **multiplexing_api**: Multiplexing API.
+ **gcc_version**: Gcc version.
+ **process_id**: The process id of the redis-migrate-tool.
+ **tcp_port**: The tcp port redis-migrate-tool listening.
+ **uptime_in_seconds**: Seconds the redis-migrate-tool running.
+ **uptime_in_days**: Days the redis-migrate-tool running.
+ **config_file**: The config file name for the redis-migrate-tool.

#### Clients:

+ **connected_clients**: The count of clients that connected at present.
+ **max_clients_limit**: The max number of clients that allows to accept at the same time.
+ **total_connections_received**: The total count of connections that received so far.

#### Group:

+ **source_nodes_count**: The nodes count of source redis group.
+ **target_nodes_count**: The nodes count of target redis group.

#### Stats:

+ **all_rdb_received**: Whether all the rdb of the nodes in source group received.
+ **all_rdb_parsed**: Whether all the rdb of the nodes in source group parsed finished.
+ **all_aof_loaded**: Whether all the aof file of the nodes in source group loaded finished.
+ **rdb_received_count**: The received rdb count for the nodes in source group.
+ **rdb_parsed_count**: The parsed finished rdb count for the nodes in source group.
+ **aof_loaded_count**: The loaded finished aof file count for the nodes in source group.
+ **total_msgs_recv**: The total count of messages that had received from the source group.
+ **total_msgs_sent**: The total count of messages that had sent to the target group and received response from target group.
+ **total_net_input_bytes**: The total count of input bytes that had received from the source group.
+ **total_net_output_bytes**: The total count of output bytes that had sent to the target group.
+ **total_net_input_bytes_human**: Same as the **total_net_input_bytes**, but convert into human readable.
+ **total_net_output_bytes_human**: Same as the **total_net_output_bytes**, but convert into human readable.
+ **total_mbufs_inqueue**: Cached commands data(not include rdb data) by mbufs input from source group.
+ **total_msgs_outqueue**: Msgs will be sent to target group and msgs had been sent to target but waiting for the response.

## OTHER COMMANDS

### shutdown [seconds|asap]

The command behavior is the following:

+ Stop the replication from the source redis.
+ Try to send the cached data in redis-migrate-tool to the target redis.
+ Redis-migrate-tool stop and exit.

Parameter:

+ **seconds**: Most of seconds that redis-migrate-tool can used to send cached data to target redis before exit. Defaults to 10 seconds.
+ **asap**: Don't care about the cached data, just exit right now.

For example, you try the **shutdown** command:
	
    $redis-cli -h 127.0.0.1 -p 8888
    127.0.0.1:8888> shutdown
    OK

## CHECK THE DATA

After migrate the data, you can use **redis_check** command to check data in the source group and target group.

Try the **redis_check** command:

    $src/redis-migrate-tool -c rmt.conf -o log -C redis_check
    Check job is running...

    Checked keys: 1000
    Inconsistent value keys: 0
    Inconsistent expire keys : 0
    Other check error keys: 0
    Checked OK keys: 1000

    All keys checked OK!
    Check job finished, used 1.041s
	
If you want check more keys, try the follow:

    $src/redis-migrate-tool -c rmt.conf -o log -C "redis_check 200000"
    Check job is running...

    Checked keys: 200000
    Inconsistent value keys: 0
    Inconsistent expire keys : 0
    Other check error keys: 0
    Checked OK keys: 200000

    All keys checked OK!
    Check job finished, used 11.962s

	
## INSERT SOME KEYS JUST FOR **TEST**

Try the **redis_testinsert** command:

    $src/redis-migrate-tool -c rmt.conf -o log -C "redis_testinsert"
    Test insert job is running...

    Insert string keys: 200
    Insert list keys  : 200
    Insert set keys   : 200
    Insert zset keys  : 200
    Insert hash keys  : 200
    Insert total keys : 1000

    Correct inserted keys: 1000
    Test insert job finished, used 0.525s
    
If you want insert more keys, try the follow:

    $src/redis-migrate-tool -c rmt.conf -o log -C "redis_testinsert 30000"
    Test insert job is running...

    Insert string keys: 6000
    Insert list keys  : 6000
    Insert set keys   : 6000
    Insert zset keys  : 6000
    Insert hash keys  : 6000
    Insert total keys : 30000

    Correct inserted keys: 30000
    Test insert job finished, used 15.486s
    
If you want insert only string type keys, try the follow:

    $src/redis-migrate-tool -c rmt.conf -o log -C "redis_testinsert string"
    Test insert job is running...

    Insert string keys: 1000
    Insert list keys  : 0
    Insert set keys   : 0
    Insert zset keys  : 0
    Insert hash keys  : 0
    Insert total keys : 1000

    Correct inserted keys: 1000
    Test insert job finished, used 0.024s
    
If you want insert some special type keys, try the follow:

    $src/redis-migrate-tool -c rmt.conf -o log -C "redis_testinsert string|set|list 10000"
    Test insert job is running...

    Insert string keys: 3336
    Insert list keys  : 3336
    Insert set keys   : 3328
    Insert zset keys  : 0
    Insert hash keys  : 0
    Insert total keys : 10000

    Correct inserted keys: 10000
    Test insert job finished, used 5.539s
    
## License

Copyright © 2016 VIPSHOP Inc.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
