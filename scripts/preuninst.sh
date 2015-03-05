if [ $1 = 0 ]; then
    /sbin/service nutcracker stop > /dev/null 2>&1
    /sbin/chkconfig --del nutcracker
fi
