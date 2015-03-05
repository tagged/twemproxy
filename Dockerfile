FROM centos:7

RUN yum install -y \
        compat-glibc-2.12 \
        tar git gcc make rpm-build ruby ruby-devel rubygems \
        autoconf automake libtool

RUN gem install fpm

RUN mkdir -p /usr/src/ \
    && cd /usr/src \
    && git clone -b build https://github.com/tagged/twemproxy.git \
    && cd twemproxy \
    && autoreconf -fvi \
    && CFLAGS="-I/usr/lib/x86_64-redhat-linux6E/include -B /usr/lib/x86_64-redhat-linux6E/lib64" LDFLAGS="-lc_nonshared" ./configure --prefix=/usr/src/twemproxy/work/usr \
    && make install

ADD . /usr/src/twemproxy

WORKDIR /usr/src/twemproxy

CMD ./build.sh
