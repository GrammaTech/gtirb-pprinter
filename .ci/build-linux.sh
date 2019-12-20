#!/bin/bash

# Called by the linux Dockerfiles 

CXX_COMPILER=$1

# Install GTIRB
rm -rf /gt/gtirb-pprinter/gtirb/build /gt/gtirb-pprinter/gtirb/CMakeCache.txt /gt/gtirb-pprinter/gtirb/CMakeFiles /gt/gtirb-pprinter/gtirb/CMakeScripts
cd /gt/gtirb-pprinter/gtirb/ && cmake ./ -Bbuild -DCMAKE_CXX_COMPILER=$CXX_COMPILER && cd build &&  make && make install

# Build gtirb-pprinter
rm -rf /gt/gtirb-pprinter/build /gt/gtirb-pprinter/CMakeCache.txt /gt/gtirb-pprinter/CMakeFiles /gt/gtirb-pprinter/CMakeScripts
mkdir -p /gt/gtirb-pprinter/build
cd /gt/gtirb-pprinter/build
cmake ../ -DCMAKE_CXX_COMPILER=$CXX_COMPILER
make -j
