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
		echo "[source]"
		echo "${SOURCE}" | base64 --decode
		echo "[target]"
		if [ -n "${REPLICATION_GROUP}" ]
		then
			echo "type: single"
			echo "servers:"
			servers=$(aws elasticache describe-replication-groups --query "ReplicationGroups[?ReplicationGroupId==\`${REPLICATION_GROUP}\`].NodeGroups[].[PrimaryEndpoint.Address]" --output text)
			for server in "${servers}"
			do 
				echo " - ${server}:6379"
		    done
		elif [ -n "${TARGET}" ]
		then
			echo "${TARGET}" | base64 --decode
		fi
		echo "[common]"
		echo ${COMMON}" | base64 --decode
		exec 1>&6 6>&-      # Restore stdout and close file descriptor #6.
	fi
	cd /migrate
	cat rmt.conf 
	exec /app/src/redis-migrate-tool -c rmt.conf "$@"
fi

exec "$@"