#!/bin/bash
set -e

if [ "$1" = 'migrate' ]; then
	if [ -n "${CONFIG_URL}" ]
	then 
		curl -s -o /migrate/rmt.conf ${CONFIG_URL}
	elif [ -n "${SOURCE}" ] 
	then
		exec 6>&1           		 # Link file descriptor #6 with stdout.
		exec > /migrate/rmt.conf     # stdout replaced with file.
		echo -e "[source]\n${SOURCE}"
		echo -e "[target]"
		if [ -n "${REPLICATION_GROUP}" ]
		then
			echo -e "type: single\nservers:"
			servers=$(aws elasticache describe-replication-groups --query "ReplicationGroups[?ReplicationGroupId==\`${REPLICATION_GROUP}\`].NodeGroups[].[PrimaryEndpoint.Address]" --output text)
			for server in "${servers}"
			do 
				echo "-${server}:6379"
		    done
		elif [ -n "${TARGET}" ]
		then
			echo -e "${TARGET}"
		fi
		echo -e "[common]\nlisten: 0.0.0.0:8888\nstep: 4\mbuf_size: 4096\n"
		exec 1>&6 6>&-      # Restore stdout and close file descriptor #6.
	fi
	cd /migrate
	cat rmt.conf 
	exec /app/src/redis-migrate-tool -c rmt.conf "$@"
fi

exec "$@"