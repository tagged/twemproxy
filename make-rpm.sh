#!/bin/bash -e

TAG=$( git describe --always )

function finish {
    docker rm twemproxy-build-$TAG
}

trap finish EXIT

docker build --tag twemproxy:$TAG .
docker run \
       --name=twemproxy-build-$TAG \
       -e 'WORKDIR=/usr/src/twemproxy/work' \
       -e 'MAIL_FROM=twemproxy@ifwe.co' \
       twemproxy:$TAG

docker cp twemproxy-build-$TAG:/usr/src/twemproxy/work/nutcracker-0.5.0-tagged1.x86_64.rpm .

