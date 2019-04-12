FROM ubuntu:16.04

# Minimum required version
ARG CMAKE_VERSION=3.9

RUN apt-get -y update && \
    apt-get -y install software-properties-common && \
    add-apt-repository ppa:jonathonf/gcc-7.1

RUN apt-get -y update && apt-get -y install gcc-7 g++-7 make git \
    build-essential binutils doxygen graphviz wget curl unzip \
    gcc-multilib g++-multilib libc++1 libc++abi1

RUN update-alternatives --install /usr/bin/cc cc /usr/bin/gcc-7 60
RUN update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-7 60

# Install CMake
RUN curl -SL https://cmake.org/files/v$CMAKE_VERSION/cmake-$CMAKE_VERSION.0-Linux-x86_64.tar.gz \
    |tar -xz --strip-components=1 -C /usr/local

# Install protobuf
RUN cd /usr/local/src \
    && wget https://github.com/google/protobuf/releases/download/v3.6.0/protobuf-cpp-3.6.0.tar.gz \
    && tar xf protobuf-cpp-3.6.0.tar.gz \
    && cd protobuf-3.6.0 \
    && ./configure \
    && make \
    && make install
RUN ldconfig

COPY . /gt/gtirb-pprinter/

# Install capstone
RUN cd /usr/local/src \
    && wget https://github.com/aquynh/capstone/archive/4.0.1.tar.gz \
    && tar xf 4.0.1.tar.gz \
    && cd capstone-4.0.1 \
    && CAPSTONE_ARCHS=x86 ./make.sh \
    && CAPSTONE_ARCHS=x86 ./make.sh install

# Install gtirb
RUN rm -rf /gt/gtirb-pprinter/gtirb/build /gt/gtirb-pprinter/gtirb/CMakeCache.txt /gt/gtirb-pprinter/gtirb/CMakeFiles /gt/gtirb-pprinter/gtirb/CMakeScripts
RUN cd /gt/gtirb-pprinter/gtirb/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=g++-7 && cd build &&  make && make install

# Build gtirb-pprinter
ENV PATH=/gt/gtirb-pprinter/bin:/gt/gtirb-pprinter/datalog_disasm/build/bin/:$PATH
RUN rm -rf /gt/gtirb-pprinter/build /gt/gtirb-pprinter/CMakeCache.txt /gt/gtirb-pprinter/CMakeFiles /gt/gtirb-pprinter/CMakeScripts
RUN mkdir -p /gt/gtirb-pprinter/build
WORKDIR /gt/gtirb-pprinter/build
RUN cmake ../ -DCMAKE_CXX_COMPILER=g++-7
RUN make -j
WORKDIR /gt/gtirb-pprinter/
ENV LD_LIBRARY_PATH /gt/gtirb-pprinter/gtirb/build/lib
