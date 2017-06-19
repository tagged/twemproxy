#!/usr/bin/env bash
# Main ci script for nutredis tests
set -xeu

function print_usage() {
    echo "Usage: $0" 1>&2
    exit 1
}

if [[ "$#" > 0 ]]; then
    echo "Too many arguments" 1>&2
    print_usage
fi

PACKAGE_NAME="nutredisci"

TAG=$( git describe --always )
DOCKER_IMG_NAME=twemproxy-build-$PACKAGE_NAME-$TAG

rm -rf twemproxy

DOCKER_TAG=twemproxy-$PACKAGE_NAME:$TAG

docker build -f ci/Dockerfile.nutredis \
   --tag $DOCKER_TAG \
   .

# Run all unit tests that apply to nutredis
TESTS="test_redis test_system"

# Run nose tests
docker run \
   --rm \
   --name=$DOCKER_IMG_NAME \
   $DOCKER_TAG \
   nosetests -v $TESTS
