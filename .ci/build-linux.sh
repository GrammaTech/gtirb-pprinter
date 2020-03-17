#!/bin/bash

set -o xtrace
set -o nounset
set -o errexit
set -o pipefail

# Called by the linux Dockerfiles

CXX_COMPILER=$1

# Build gtirb-pprinter
rm -rf /gt/gtirb-pprinter/build /gt/gtirb-pprinter/CMakeCache.txt /gt/gtirb-pprinter/CMakeFiles /gt/gtirb-pprinter/CMakeScripts
mkdir -p /gt/gtirb-pprinter/build
cd /gt/gtirb-pprinter/build
cmake ../ -DCMAKE_CXX_COMPILER=$CXX_COMPILER
make -j
