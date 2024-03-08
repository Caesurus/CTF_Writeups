# Use Debian Jessie as the base image
FROM debian:jessie

# Add trusted flag to avoid expired GPG key issue
RUN echo "deb [trusted=yes] http://archive.debian.org/debian/ jessie main contrib non-free" > /etc/apt/sources.list \
    && echo "deb-src [trusted=yes] http://archive.debian.org/debian/ jessie main contrib non-free" >> /etc/apt/sources.list \
    && echo "deb [trusted=yes] http://archive.debian.org/debian-security/ jessie/updates main" >> /etc/apt/sources.list

# Install standard development tools
RUN apt-get update -o Acquire::Check-Valid-Until=false && apt-get install -y \
    build-essential \
    libncurses5-dev \
    bison \
    flex \
    libssl-dev \
    bc wget unzip file gettext cpio python rsync vim
RUN cd /tmp/; wget http://ftp.gnu.org/gnu/texinfo/texinfo-4.13a.tar.gz; tar xvf texinfo-4.13a.tar.gz; cd texinfo*; ./configure && make && make install

RUN cp /bin/mkdir /usr/bin/mkdir
# Set up the environment for 64-bit compilation
ENV CC=gcc
ENV CXX=g++

# Other setup can go here (like copying kernel source code, etc.)

CMD ["/bin/bash"]

