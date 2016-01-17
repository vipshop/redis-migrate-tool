# redis-migrate-tool

**redis-migrate-tool** is a convenient and useful tool for migrating data between [redis](https://github.com/antirez/redis). 

## Build

To build redis-migrate-tool:

    $ cd redis-migrate-tool
    $ autoreconf -fvi
	$ ./configure
    $ make
    $ src/redis-migrate-tool -h

## RUN

	src/redis-migrate-tool -c rmt.conf -o log -d

## Configuration

Config file has three parts: source, target and common.

### source OR target:

+ **type**: The group redis type. Possible values are:
 + single
 + twemproxy
 + redis cluster
 + rdb file
+ **servers:**: The list of redis address in the group. If type is twemproxy, this is same as the twemproxy config file. If type is rdb file, this is the file name.
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
+ **threads**: The max threads count can be used by redis-migrate-tool. Defaults to the cpu core count.
+ **step**: The step for parse request. The higher the number, the more quickly to migrate, but the more memory used. Defaults to 1.
+ **mbuf_size**: Mbuf size for request. Defaults to 512.
+ **noreply**: A boolean value that decide whether to check the target group replies. Defaults to false.


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
	threads: 2
	noreply: true
	step: 10
	mbuf_size: 1024
	

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
	noreply: false
	step: 5
	mbuf_size: 512

## License

Copyright 2012 Deep, Inc.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
