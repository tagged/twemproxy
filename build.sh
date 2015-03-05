#!/bin/bash -e

mkdir -p work/etc/rc.d/init.d/
cp scripts/nutcracker.init work/etc/rc.d/init.d/nutcracker
chmod +x work/etc/rc.d/init.d/nutcracker

pushd work

fpm -n nutcracker -v 0.5.0 --iteration tagged1 \
    --after-install ../scripts/postinst.sh \
    --before-remove ../scripts/preuninst.sh \
    -s dir -t rpm .
