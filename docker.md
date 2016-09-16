### Docker integration

The Dockerfile will build an image based on `debian:jessie` with the executable for the migrate tool, and will also install the aws cli to find the endpoint of the primary node in an elastic cache for a replication group.
The container can be run by either:
- mounting a local volume in the /migrate volume with a prebuilt `rmt.conf` file
- or, defining environment variables to create the configuration dynamically.

### Variables
- SOURCE: a string with new line delimiters ('\n') that defines the source redis (such as `type: single\nservers:\n-127.0.0.1:6379`)
- TARGET: an optional string with new line delimiters that defines the target redis (as above). 
- COMMON:  a string with new lines delimiter that defines the common options (as above)
- REPLICATION_GROUP: Alternatively to target, an Elastic cache replication group id can be specified and the container will query for the corresponding primary endpoint.
- AWS_DEFAULT_REGION: Optional, the AWS region.
- AWS_ACCESS_KEY_ID: Optional, the AWS access key.
- AWS_SECRET_ACCESS_KEY: Optional, the AWS secret key

### Compose file
The docker-compose.yml is included just for testing the application, it creates a source and target redis container and runs the migrate process. 
