#!/bin/bash
set -xe
#file   : travis.sh
#author : ning
#date   : 2014-05-10 16:54:43

#install deps if we are in travis
if [ -n "$TRAVIS" ]; then
    sudo apt-get install socat

    #python libs
    sudo pip install redis
    sudo pip install nose

    sudo pip install git+https://github.com/andymccurdy/redis-py.git@2.10.3
    sudo pip install git+https://github.com/idning/python-memcached.git#egg=memcache
fi

#build twemproxy
CFLAGS="-ggdb3 -O0" autoreconf -fvi && ./configure --enable-debug=log && make

if [ ! -x src/nutredis ]; then
	echo "Failed to build nutredis" 1>&2
	exit 1
fi
ln -s `pwd`/src/nutredis  tests/_binaries/nutredis
ln -s `pwd`/src/nutredis  tests/_binaries/nutcracker
cp `which redis-server` tests/_binaries/
cp `which redis-server` tests/_binaries/redis-sentinel
cp `which redis-cli` tests/_binaries/
cp `which memcached` tests/_binaries/

#run test
echo "TODO: Fix nosetests on the build-nutredis branch."
# cd tests/ && nosetests --nologcapture -x -v
