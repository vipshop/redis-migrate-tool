# redis-migrate-tool

**redis-migrate-tool** is a convenient and useful tool for migrating data between [redis](https://github.com/antirez/redis). 

It is based on redis replication.

In the process of migrating data, the source redis also can provide services for users. 

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

## Configuration

Config file has three parts: source, target and common.

### source OR target:

+ **type**: The group redis type. Possible values are:
 + single
 + twemproxy
 + redis cluster
 + rdb file
+ **servers:**: The list of redis address in the group. If type is twemproxy, this is same as the twemproxy config file. If type is rdb file, this is the file name.
+ **redis_auth**: Authenticate to the Redis server on connect. Now just for source redis group.
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
+ **dir**: Work directory. Defaults to the current directory.


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
	listen: 0.0.0.0:34345
	threads: 2
	step: 10
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
	step: 1
	mbuf_size: 512
	
	
Migrate data from rdb file to redis cluster.

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
	threads: 1
	step: 5
	mbuf_size: 512
	source_safe: false

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
	config_file:rmt.conf
	
	# Clients
	connected_clients:1
	max_clients_limit:100
	total_connections_received:3
	
	# Stats
	all_rdb_parsed:1
	total_msgs_recv:7753587
	total_msgs_sent:7753587
	total_net_input_bytes:234636318
	total_net_output_bytes:255384129
	total_net_input_bytes_human:223.77M
	total_net_output_bytes_human:243.55M
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

#### Stats:

+ **all_rdb_parsed**: Whether the all the rdb of the nodes in source group parsed finished.
+ **total_msgs_recv**: The total count of messages that had received from the source group.
+ **total_msgs_sent**: The total count of messages that had sent to the target group.
+ **total_net_input_bytes**: The total count of input bytes that had received from the source group.
+ **total_net_output_bytes**: The total count of output bytes that had sent to the target group.
+ **total_net_input_bytes_human**: Same as the **total_net_input_bytes**, but convert into human readable.
+ **total_net_output_bytes_human**: Same as the **total_net_output_bytes**, but convert into human readable.
	
## License

Copyright 2012 Deep, Inc.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
